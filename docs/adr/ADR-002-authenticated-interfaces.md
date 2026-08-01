<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-002 — Authenticated inter-process interfaces

**Status:** accepted (M1, 2026-08-01). **Spec:** §3 (three processes, demo authentication), §5 (dialogue boundary rules), §6 criterion 4, §10 M1 (world-id seams, config-driven endpoints).

## Context

Three OS processes make "the model proposes, a component outside the model decides, the executing service
verifies again" a process boundary rather than a comment. Static per-role tokens (principal, case officer,
applicant) and per-process credentials ride every call, and every decision records the authenticated
role. The boundary that matters: **the orchestrator can reach no authority-changing endpoint**, and it can
neither read a person's credential nor forge a confirmation. This is demo-grade authentication by
declared limit (§9), not an IAM design.

## Decision

### 1. Processes, ports, origins

| Process | Package | Port env (default) | Serves |
|---|---|---|---|
| Authorization service | `gate-core` | `AUTHZ_PORT` (7801) | Gate API, record API, **governance console** |
| Orchestrator | `consoles` + loop | `ORCHESTRATOR_PORT` (7802) | Agent loop, **case console** |
| Services host | `services-mock` | `SERVICES_PORT` (7803) | registry / filing / notification |

All three bind explicitly to `RUNTIME_HOST` (default `127.0.0.1`), never `0.0.0.0`. Base URLs are
*derived*, never hard-coded: `http://${RUNTIME_HOST}:${port}`. One canonical spelling is used everywhere —
`localhost` and `127.0.0.1` are different browser origins, and mixing them silently breaks the CORS rule
in §5. Every cross-process URL is config-driven (the §10 sandbox seam).

Request bodies are capped at 1 MiB; anything larger is rejected before parsing.

### 2. Credentials — format, custody, verification

Two credential families, both opaque static bearer tokens of 32 random bytes, hex-encoded, generated once
by a tooling script and written to the gitignored `.env.local`:

| Env var | Kind | Held by |
|---|---|---|
| `AUTHZ_TOKEN_PRINCIPAL` | role `principal` | a human, pasted into the governance console |
| `AUTHZ_TOKEN_CASE_OFFICER` | role `case_officer` | a human, pasted into the case console / dialogue control |
| `AUTHZ_TOKEN_APPLICANT` | role `applicant` | a human, pasted into the extract view |
| `AUTHZ_TOKEN_PROC_ORCHESTRATOR` | process `proc:orchestrator` | orchestrator process only |
| `AUTHZ_TOKEN_PROC_SERVICES_HOST` | process `proc:services_host` | services-host process only |
| `SERVICES_TOKEN_PROC_AUTHZ` | process `proc:authz` | authorization service, for reconciliation probes |

- Transport: `Authorization: Bearer <token>` on every call. No cookies anywhere — which also means no
  CSRF surface on the data routes: there is no ambient credential for a cross-site form to ride, a
  foreign origin cannot read another origin's `localStorage`, and it cannot make the browser attach an
  `Authorization` header (ADR-004 completes the dialogue-control side).
- Loading: `node --env-file=.env.local` (Node ≥ 20.6, no dependency). **Startup validation, fail closed:**
  every required variable present, ≥ 64 hex chars, and all values mutually distinct. Two roles sharing a
  token would silently collapse the ACL, so a duplicate is a startup error.
- Verification: constant-time compare (`crypto.timingSafeEqual` after a length check).
- **Tokens never appear in logs, records, or error bodies.** Only the resolved label (`role:principal`,
  `proc:orchestrator`) is logged or recorded — not the value, not a prefix.

### 3. Who may call what — deny-by-default route ACL

A static table in the authorization service maps route → allowed credential labels. **A route with no ACL
entry is denied to everyone**, so adding a route without a decision fails closed. A startup assertion
enumerates registered routes against the table and refuses to serve on a mismatch.

Authorization service, all data routes under `/w/{world_id}/…`:

| Route | Allowed |
|---|---|
| `POST /proposals` (submit frozen proposal → ruling) | `proc:orchestrator` |
| `GET /rulings/{id}` (status projection, §7) | `proc:orchestrator` (own submissions), `proc:services_host` |
| `GET /mandates/{id}/approved-models` (picker source, card-verified) | `proc:orchestrator`, `role:case_officer` |
| `POST /commit-verify` | **`proc:services_host` only** |
| `POST /effects/{effect_id}/outcome` | **`proc:services_host` only** |
| `POST /mandates` · `POST /mandates/{id}/amend` · `POST /mandates/{id}/revoke` | **`role:principal` only** |
| `GET /mandates` (read) | `role:principal`, `role:case_officer` (envelope they work under) |
| `GET /escalations` (inbox) | `role:principal`, `role:case_officer` — each sees only escalations routed to it |
| `GET /escalations/{id}` (display mirror, §7 projection) | `proc:orchestrator` (read-only), `role:principal`, `role:case_officer` |
| `POST /escalations/{id}/disposition` | **the escalation's eligible role token only** |
| `POST /escalations/{id}/response` (dialogue answer) | **the routed conversation partner's role token only** (ADR-004) |
| `GET /records…` · `POST /records/verify` | `role:principal` (full), `role:case_officer` (case-scoped) |
| `GET /extract` (server-side scoped applicant extract) | **`role:applicant` only** |
| `GET /console/*` (governance console assets) | unauthenticated static assets, no data |
| `GET /healthz` | unauthenticated, no world, no data |

Orchestrator: `GET /console/*` unauthenticated assets; `POST /w/{w}/cases/{id}/messages`,
`GET /w/{w}/cases/{id}/state`, `GET /w/{w}/models` all `role:case_officer`.
Services host: `POST /w/{w}/services/{service}/execute` `proc:orchestrator`;
`GET /w/{w}/effects/{idempotency_key}` (read-only reconciliation probe) `proc:authz`; `GET /healthz` open.

**The orchestrator's credential appears on exactly four authorization-service routes** — proposal
submission, ruling read, approved-model read, and the read-only escalation mirror ADR-004 §7 requires so
the case console can render a pending question. Nothing else: it is denied on mandate
grant/amend/revoke, escalation disposition, dialogue response, `commit-verify`, effect outcome, record
read, verify, and extract. Reading escalation *state* is not authority-changing, and §7's projection
bounds what that read returns. The orchestrator also never receives a commit token: the services host
obtains its own from `commit-verify` and never trusts the orchestrator's claim of approval.

ADR-004 writes the two escalation routes without their world prefix (`{AUTHZ_ORIGIN}/escalations/…`);
the canonical form is the world-scoped one above.

Denials are explicit and recorded: unknown or absent credential → 401; valid credential without route
permission → 403. Both are written to the access-log chain — a rejected authority-changing attempt is
evidence, so the POC prefers a recorded 403 over an obscuring 404.

### 4. On-behalf-of is provenance, never authority

Inter-process calls may carry `X-On-Behalf-Of-Role` and `X-Session-Id`. These are **claims by the calling
process** and are recorded as such. Every record entry therefore carries two distinct fields:

```json
{"authenticated_actor":"proc:orchestrator","claimed_actor":{"role":"case_officer","session":"s_41c"}}
```

`claimed_actor` is never an input to an authority decision. Anything that turns on a person's standing —
an escalation disposition, a dialogue confirm/correct/permit, a mandate change — is accepted **only** when
the person's own role token arrives on a direct browser→authorization-service call. This is the
mechanical form of spec §5's boundary rule: the orchestrator neither serves the credential-bearing control
nor carries the answer, so it can neither read the token nor forge a confirmation or a permission.

### 5. Browser access, CORS, and console token custody

The governance console — and, per ADR-004, the dialogue response control reached by deep link rather than
iframe — is served by the **authorization service's own origin**, so every credential-bearing browser call
is same-origin.

**CORS allowlist = the authorization service's own origin, which means no CORS headers are emitted at
all.** Cross-origin credentialed fetches simply fail in the browser. The orchestrator's origin
(`:7802`) is deliberately *not* allowlisted; that omission is what enforces the §5 boundary rule at the
browser level rather than only in the ACL. This is stricter than "allow the governance-console origin"
and identical in intent, since that origin *is* the service's own. Two companions: every governance-console
page ships `Content-Security-Policy: frame-ancestors 'none'`, so the no-embed decision is technically
enforced; and on authority-changing routes a **present** `Origin` header that is not the service's own is
403. An *absent* `Origin` is allowed — that is a non-browser client, and beat 17's raw API client must
reach the endpoint so the endpoint can refuse it on the merits rather than at the door.

Consequence for the case console: it holds no role token and makes no credentialed call to the
authorization service. It renders a pending question read-only from the orchestrator's non-authoritative
mirror (§7) and links the responder to the governance origin to answer. It learns that an action may
proceed from `GET /rulings/{id}`: that projection reports the ruling's status and, when an escalation's
"allow within scope" disposition mints a successor, its `successor_ruling_id`.

Token custody in the browser is demo-grade and explicit: a token-entry field on the governance origin,
held in that origin's `localStorage` (not `sessionStorage` — ADR-004's deep link opens a new tab, which
would start empty), sent as a bearer header. No login, no session exchange, no cookie.

### 6. World-id keying

Every data route is world-scoped by construction: `/w/{world_id}/…`. There is no default world and no
implicit fallback — a request without the segment is a 404. `world_id` matches
`^[a-z0-9][a-z0-9-]{0,31}$`, which also makes it a safe path segment (no `.`, `..`, `/`, `\`), and the
Windows reserved device names (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`) are rejected,
because the world id becomes a directory name.

- Every stored object carries `world_id` as its first field; a transaction touches exactly one world.
- Storage is per world: `records/{world_id}/{wal,action,access}.jsonl` (ADR-003's three streams) and
  `records/{world_id}/effects/`. One record chain per world (§10).
- The world mutex and the writer lock (ADR-001) are per world; ADR-003 keeps one composite digest over
  all worlds with the per-world heads listed inside it.
- **Credentials are issued for a world.** The demo world is `w-demo` (config `DEMO_WORLD_ID`, matching
  ADR-003's checkpoint example) and all six credentials are scoped to it; a token presented against
  another world's path is 403. That is the whole v1.1 per-visitor-sandbox seam: mint a world-scoped
  token, create a world directory, change nothing in the transactional core.
- The demo world is deliberately **not** named `default`, so no reader mistakes it for a fallback: there
  is none.
- No route reads across worlds.

### 7. Response projections and access logging

Route permission alone would still leak: a "ruling read" that returned the whole ruling would hand the
orchestrator the evidence refs and the screening rationale. Every response is therefore a **fixed
allowlist projection**, decided per route and per credential:

- ruling → `{ruling_id, verdict, ux_class, reason, status, successor_ruling_id, validity_window}`;
- escalation mirror → `{escalation_id, status, question_text, contract (the six fields),
  proposal_revision_ref, response_bound, terminal_disposition?}` — no record entries, no evidence
  payloads, no responder identity beyond the role.

Neither carries record content or applicant data.

Every route in the record family (`/records…`, `/records/verify`, `/extract`) appends an entry to the
**access-log chain** before returning, so verification never mutates the chain it verifies, and the
applicant's extract is assembled server-side in the authorization service — never in the orchestrator.
Escalation-status polls read state rather than record entries and are deliberately not access-logged
(ADR-004 §7), or polling would drown the chain.

### 8. Declared limits (demo-grade, stated in the README)

Static tokens with **no rotation, no expiry, and no revocation** short of editing `.env.local` and
restarting. All three processes run as one OS user on one machine, so there is no OS-level isolation
behind the process boundary. A bearer token in `localStorage` is readable by any script on that origin —
tolerable only because that origin serves no third-party content and ships a strict CSP.
Competence and independence in the intervention contract remain *declared*, not verified. Role binding is
testable; identity is not established.

## Consequences

**Testable now.** A route-coverage test enumerates every registered route and fails if any lacks an ACL
entry. A negative-authorization test replays the orchestrator's credential against every
authority-changing route and asserts 403 plus an access-log entry — the mechanical form of the "no bypass
path exists" invariant (criterion 4). A forged `X-On-Behalf-Of-Role: principal` from the orchestrator on a
disposition route is rejected and recorded. Cross-world token use is 403. A duplicate or short token in
`.env.local` fails startup. Beat 17's raw-API client works precisely because the ACL and the console are
independent layers: the console renders only permitted dispositions, and the API still refuses an
out-of-scope one — and `commit-verify` refuses it again.

**Deferred, by decision.** No rotation, expiry, refresh, or revocation list. No mTLS or signed
inter-process requests — the process credential is a shared secret, and a local attacker who can read
`.env.local` has everything. No per-user identity, directory, or audit of *who* holds a role token. No
rate limiting beyond the body cap. The v1.1 sandbox needs a token-minting path and a world lifecycle
(create, expire, delete); this ADR reserves the seam and specifies nothing further.

**Implementation follow-up.** `.env.local.example` must gain the six token variables, `RUNTIME_HOST`,
`DEMO_WORLD_ID`, and the three port variables — alongside ADR-007's `GATE_HMAC_KEY` /
`GATE_HMAC_KEY_ID` — before M2; this ADR does not change that file.
