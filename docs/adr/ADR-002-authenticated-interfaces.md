<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-002 — Authenticated inter-process interfaces

**Status:** accepted (M1, 2026-08-01). **Spec:** §3 (three processes, demo authentication), §5 (dialogue boundary rules), §6 criterion 4, §10 M1 (world-id seams, config-driven endpoints).

**Amendment (M3 review follow-up, 2026-08-02):** authenticated HTTP adapters, not in-process actor guards, own access-denial evidence because only the adapters can attest the route and verified credential.

**Amendment (M4 authority review follow-up, 2026-08-02):** the adapter passes schema-validated named route parameters to handlers and accepts a bare wildcard root such as `/console`. Unauthenticated ingress records only a bounded number of detailed 401s, an initial 429 suppression marker, and a counted summary when the process window rolls over; authenticated refusals remain individually durable.

**Amendment (M4 native-process slice, 2026-08-02):** the local supervisor passes credential subsets rather than the whole environment. It one-way derives distinct case-console and orchestrator→services audience tokens from the existing high-entropy base credentials; the derived values are never stored. A receiving process therefore cannot replay its narrower credential at the authorization service.

**Amendment (M4 native-process review, 2026-08-02):** proposal submission returns only the §7 ruling
projection; internal bindings, nonces, evidence, reservations, and record-entry ids do not cross into the
orchestrator. Services-host HTTP denials are reported over a services-only authorization endpoint; each
authenticated denial and detailed unauthenticated denial is durably appended before its response, and a
durable suppression marker precedes the first coalesced 429.

**Amendment (M4 read-side slice, 2026-08-03):** every previously reserved read route now has an
authorization-owned fixed projection. Record and extract routes read verified materialized chains, append
their access evidence before returning, and expose checkpoint/open-window facts without turning them into
an assurance signal. The orchestrator's escalation read is a status mirror only; intervention contracts
remain confined to the authoritative origin and the role to which they are routed.

**Amendment (M4 governance-console slice, 2026-08-03):** the authorization process preloads the separate
MIT console assets before binding and serves their shell, script, and stylesheet through fixed open route
ids. Every console response carries a strict self-only CSP including `frame-ancestors 'none'`, and no CORS
or cookie header. The principal may read the existing fixed approved-model projection so the mandate
surface can show the signed-card evidence it governs; this adds no mutation permission and exposes no
binding, nonce, reservation, or aggregate trust signal.

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
| `AUTHZ_TOKEN_CASE_OFFICER` | role `case_officer` | a human, pasted only into authorization-origin governance / dialogue controls |
| `AUTHZ_TOKEN_APPLICANT` | role `applicant` | a human, pasted into the extract view |
| `AUTHZ_TOKEN_PROC_ORCHESTRATOR` | process `proc:orchestrator` | orchestrator process only |
| `AUTHZ_TOKEN_PROC_SERVICES_HOST` | process `proc:services_host` | services-host process only |
| `SERVICES_TOKEN_PROC_AUTHZ` | process `proc:authz` | authorization service, for reconciliation probes |

Two narrower audience credentials are derived in memory by the local supervisor and passed only to the
target child process: `ORCHESTRATOR_TOKEN_CASE_OFFICER = H("orchestrator-case-officer", AUTHZ_TOKEN_CASE_OFFICER)`
and `SERVICES_TOKEN_PROC_ORCHESTRATOR = H("services-proc-orchestrator", AUTHZ_TOKEN_PROC_ORCHESTRATOR)`.
Here `H` is the domain-prefixed SHA-256 derivation implemented by `deriveAudienceToken`; the source tokens
are random 256-bit values, so a derived value does not reveal the authorization-service credential. These
are protocol credentials, not new stored secrets. The authorization process receives the five inbound
credentials it verifies, its services-probe credential, and the HMAC pair; services receives its
authorization credential, the derived execute
credential, its probe credential, and the HMAC pair; the orchestrator receives only its authorization
process credential and the two narrower credentials it must verify or present. Model API keys are not
passed by this M4 headless supervisor.

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
| `GET /mandates/{id}/approved-models` (picker and principal card-evidence source, card-verified) | `proc:orchestrator`, `role:principal`, `role:case_officer` |
| `POST /commit-verify` | **`proc:services_host` only** |
| `POST /effects/{effect_id}/outcome` | **`proc:services_host` only** |
| `POST /access-events` (narrow services-host denial evidence) | **`proc:services_host` only** |
| `POST /mandates` · `POST /mandates/{id}/amend` · `POST /mandates/{id}/revoke` | **`role:principal` only** |
| `GET /mandates` (read) | `role:principal`, `role:case_officer` (envelope they work under) |
| `GET /escalations` (inbox) | `role:principal`, `role:case_officer` — each sees only escalations routed to it |
| `GET /escalations/{id}` (display mirror, §7 projection) | `proc:orchestrator` (read-only), `role:principal`, `role:case_officer` |
| `POST /escalations/{id}/disposition` | **the escalation's eligible role token only** |
| `POST /escalations/{id}/response` (dialogue answer) | **the routed conversation partner's role token only** (ADR-004) |
| `POST /escalations/{id}/revision` (continue after narrow/modify) | **`proc:orchestrator` only** |
| `GET /records…` · `POST /records/verify` | `role:principal` (full), `role:case_officer` (case-scoped) |
| `GET /extract` (server-side scoped applicant extract) | **`role:applicant` only** |
| `GET /console/*` (governance console assets) | unauthenticated static assets, no data |
| `GET /healthz` | unauthenticated, no world, no data |

Orchestrator: `GET /console/*` unauthenticated assets; `POST /w/{w}/cases/{id}/messages`,
`GET /w/{w}/cases/{id}/state`, `GET /w/{w}/models` all `role:case_officer`, authenticated with the
orchestrator-audience derived credential rather than the authorization-service role credential.
The bounded headless transport slice also exposes `POST /w/{w}/actions/execute` under that same
orchestrator-audience credential. It accepts an already-frozen synthetic proposal solely to drive the
cross-process gate/commit/effect path; it is not the case-dialogue API and does not complete the browser
console contract.
Services host: `POST /w/{w}/services/{service}/execute` `proc:orchestrator`;
`GET /w/{w}/effects/{idempotency_key}` (read-only reconciliation probe) `proc:authz`; `GET /healthz` open.
`commit-verify`, effect outcomes, and reconciliation probes carry both the current services-host boot id
and the persistent services-ledger id; only absence under the same ledger id can release a commitment.

**The orchestrator's credential appears on exactly five authorization-service routes** — proposal
submission, revised-proposal continuation, ruling read, approved-model read, and the read-only escalation
mirror ADR-004 §7 requires so the case console can render a pending question. Nothing else: it is denied on mandate
grant/amend/revoke, escalation disposition, dialogue response, `commit-verify`, effect outcome, record
read, verify, and extract. Reading escalation *state* is not authority-changing, and §7's projection
bounds what that read returns. The orchestrator also never receives a commit token: the services host
obtains its own from `commit-verify` and never trusts the orchestrator's claim of approval.

ADR-004 writes the two escalation routes without their world prefix (`{AUTHZ_ORIGIN}/escalations/…`);
the canonical form is the world-scoped one above.

Denials are explicit: unknown or absent credential → 401, then 429 after the bounded detailed-evidence
allowance; valid credential without route permission → 403. Authenticated refusals are written
individually to the access-log chain. Unauthenticated floods are globally coalesced per process window:
up to the configured detailed limit is written, followed by one lower-bound suppression marker. At window
rollover a final entry records the total suppressed count, so an attacker cannot turn durable evidence into
an unbounded WAL/fsync workload. A crash before rollover leaves the initial marker as an honest lower bound.

The authenticated HTTP adapter emits those entries because it knows the requested route and verified
credential. Core actor guards are defence in depth and do not fabricate HTTP evidence; M4's adapter
must append the denial before returning 401/403 without calling the core operation.
For the coalesced unauthenticated case it appends the suppression marker before the first 429.
The services adapter uses its process credential to report only a closed denial shape and canonical
services route id to authorization; it cannot append arbitrary record content. If that append is unavailable,
services fails the request without returning an unrecorded 401/403.

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

Consequence for the case console: it holds no **authorization-service** role token and makes no credentialed
call to the authorization service. Its orchestrator-audience credential is not accepted by the authorization
service. It renders a pending question read-only from the orchestrator's non-authoritative
mirror (§7) and links the responder to the governance origin to answer. It learns that an action may
proceed from `GET /rulings/{id}`: that projection reports the ruling's status and, when an escalation's
"allow within scope" disposition mints a successor, its `successor_ruling_id`.

The headless M4 slice has no browser delivery path for `ORCHESTRATOR_TOKEN_CASE_OFFICER`; injecting it into
the orchestrator child is sufficient only for synthetic HTTP tests. The browser console must not ship until
an authorization-origin, one-time handoff is specified and implemented. That handoff may deliver a narrow
case-console session but must never send the authorization-service role token to the orchestrator, print
either credential, or persist the derived static credential in a repository or runtime record.

Token custody in the browser is demo-grade and explicit: a token-entry field on the governance origin,
held in that origin's `localStorage` (not `sessionStorage` — ADR-004's deep link opens a new tab, which
would start empty), sent as a bearer header. No login, no session exchange, no cookie.

The static console has no inline executable content and no third-party dependency. Its external module and
stylesheet are same-origin resources; its browser fetches use relative paths, omit cookies, and keep token
values out of URLs, rendered output, and error messages. The principal surface calls only mandate,
approved-card, routed-escalation, and record routes already owned by this service. The applicant surface
calls only the server-side scoped-extract route. UI disposition controls are intersected with the general
disposition vocabulary and appear only while the returned contract is open; the endpoint remains the
authority and can still refuse a stale or forged request. Dialogue responses remain a later M4 slice.

### 6. World-id keying

Every data route is world-scoped by construction: `/w/{world_id}/…`. There is no default world and no
implicit fallback — a request without the segment is a 404. `world_id` matches
`^[a-z0-9][a-z0-9-]{0,31}$`, which also makes it a safe path segment (no `.`, `..`, `/`, `\`), and the
Windows reserved device names (`con`, `prn`, `aux`, `nul`, `com1`–`com9`, `lpt1`–`lpt9`) are rejected,
because the world id becomes a directory name.
Handlers receive only schema-validated named parameters (`world_id`, opaque `id`) from the adapter;
wildcard tails are not promoted to authority inputs and must not be re-parsed from the raw pathname.

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

- proposal submission → `{ruling: {ruling_id, verdict, ux_class, reason, status,
  successor_ruling_id, validity_window}, escalation_id}`;
- ruling → `{ruling_id, verdict, ux_class, reason, status, successor_ruling_id, validity_window}`;
- approved models → for the orchestrator, case officer, and principal, the mandate id/version/state and
  acting-role entries only, each carrying its pinned
  approval, current signed public card, current digest and verifying key id, factual
  `current | superseded | withdrawn` and signature/integrity states, and the effective data-class
  intersection. This is the find → check evidence view, not a green-light or aggregate trust signal;
- mandate list → current-version envelope fields including authority chain, limits, substitution rules,
  and approved-model references, but no HMAC binding, replay mechanics, or mutation endpoint;
- escalation list → only escalations routed to the authenticated role, with route, state, response bound,
  permitted dispositions, terminal disposition, and proposal-revision reference;
- routed escalation detail on a role credential → the list fields plus ruling projection, question text
  where a dialogue event supplies one, and the six-field contract. The orchestrator credential receives
  only `{escalation_id, status, proposal_revision_ref, response_bound, terminal_disposition}` — never the
  question, contract, route, ruling, record entries, evidence payloads, or responder identity;
- record view → verified action- and access-chain envelopes (`seq`, `prev_hash`, `entry_hash`) with their
  schema-validated entries. The principal sees the world; the case-officer token sees the single demo
  world's case scope. Their disk heads must equal the current durable writer heads, so a same-boot valid-prefix
  rollback is an alarm rather than an apparently valid shorter view. No route reads across worlds;
- record verification → `no-divergence-detected | alarm`, the named checkpoint and only this world's
  stream rows, latest remotely confirmed checkpoint facts when available, and explicit open-window facts;
- applicant extract → server-side action, authority/ruling, effect, intervention-summary, challenge route,
  and local-receipt projections for the single synthetic applicant world. It excludes evidence payloads,
  bindings, nonces, reservations, idempotency keys, and full internal records.

The orchestrator-facing ruling, model, and escalation-status projections carry neither record content nor
applicant extract data.

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
entry. A negative-authorization test replays the orchestrator's credential with the declared HTTP method
against every route it is denied and asserts 403 plus an access-log entry — the mechanical form of the "no bypass
path exists" invariant (criterion 4). A forged `X-On-Behalf-Of-Role: principal` from the orchestrator on a
disposition route is rejected and recorded. Cross-world token use is 403. A duplicate or short token in
`.env.local` fails startup. Beat 17's raw-API client works precisely because the ACL and the console are
independent layers: the console renders only permitted dispositions, and the API still refuses an
out-of-scope one — and `commit-verify` refuses it again.

**Deferred, by decision.** No rotation, expiry, refresh, or revocation list. No mTLS or signed
inter-process requests — the process credential is a shared secret, and a local attacker who can read
`.env.local` has everything. No per-user identity, directory, or audit of *who* holds a role token. No
general authenticated rate limiting beyond the body cap and the bounded unauthenticated-ingress control
above. The v1.1 sandbox needs a token-minting path and a world lifecycle
(create, expire, delete); this ADR reserves the seam and specifies nothing further.
Authenticated 403s remain one durable transaction per attempt by design. The unauthenticated limiter is
global per process, so one flooder can suppress detailed evidence for peers during the short window; this
avoids an attacker-controlled, unbounded per-peer key map.

**Implementation follow-up.** `.env.local.example` must gain the six token variables, `RUNTIME_HOST`,
`DEMO_WORLD_ID`, and the three port variables — alongside ADR-007's `GATE_HMAC_KEY` /
`GATE_HMAC_KEY_ID` — before M2; this ADR does not change that file.
