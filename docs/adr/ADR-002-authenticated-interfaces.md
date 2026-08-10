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

**Amendment (M4 case-session handoff protocol, 2026-08-03):** the authorization-origin console mints a
single-use, boot-bound handoff for an authenticated case officer; an exact-origin/exact-window browser
exchange carries it to the fixed orchestrator handoff page, and the orchestrator redeems it through its
authenticated process channel. Redemption creates an independent, short-lived, case-bound browser session
at the orchestrator origin. The existing derived case-officer credential remains a headless synthetic-test
seam only and is never delivered to a browser. The exchange authenticates a console session but grants no
action authority.

**Amendment (M4 acceptance challenge path, 2026-08-03):** an applicant-authenticated, Origin-guarded
challenge route binds an action id to one existing record entry. Authorization appends the factual correction,
marks reliance withdrawn pending review, and opens one principal-owned routing obligation atomically. It does
not rewrite the contested entry, reverse an effect, or claim an independent remedy decision.

**Amendment (M5.2 authorization-resolved projection boundary, 2026-08-03):** authorization exposes one
authenticated read-only acting-projection route to `proc:orchestrator`. Its strict request names only the
pinned mandate and acting-card approval; authorization injects the configured case and acting role, reloads
the signed card, computes the mandate/card clearance intersection, projects whole items, and access-records
the disclosure. No caller may supply case, role, items, tags, or effective clearances. The bounded POC has no
case-to-mandate relation, so the route fails closed unless exactly one mandate is active in the world and the
request's mandate id/version names that sole envelope; the orchestrator cannot choose among active mandates.

**Amendment (M5.3 model-output admission boundary, 2026-08-04):** authorization exposes one non-authorizing,
Origin-guarded process route to `proc:orchestrator`. Its strict body carries a turn id, the exact approved
mandate/card/model references, the provider-reported served id, an authorization-projection digest, and bounded
model text. Authorization injects the configured case and acting role, recomputes the current projection and
card evidence, verifies the digest and served-id policy, derives turn-level tags, and applies the two red lines
the specification assigns directly to output control. The fixed response and access record contain only
bindings, counts, tags, reasons, and digests—never model text—and state `authority_effect: none`. Provider and
browser ingress remain closed, so this slice exposes no model response to a person and grants no action authority.

**Amendment (M5.4 containment-only model turn, 2026-08-04):** the orchestrator edge composes the existing
acting-projection and output-admission routes around one configured OpenAI-compatible adapter. It verifies the
adapter's lane/requested-id identity before disclosure, accepts no caller-supplied messages or projection scope,
and halts the lane on authorization, provider, protocol, binding, or withheld-output failure. An admitted result
is copied into a process-private quarantine exposing metadata and destruction only—there is no content reader or
release consumer. This coordinator is not wired into the native process or any HTTP/browser route; `/messages`
remains `501`, and `runtime:start` still cannot initiate a provider call.

**Amendment (M5.5 durable model-call lifecycle, 2026-08-04):** the raw acting-projection process route is
removed. `proc:orchestrator` must begin a boot-bound, single-use call through authorization before projection
disclosure, then consume that reference through output admission or a fixed failure report. All three routes
are non-authorizing, Origin-guarded, and access-recorded. Failure evidence is restricted to the declared
timeout, unavailable, malformed, tool-call-refused, or authorization-invalidated class plus binding and
provider-disclosure metadata; prompts, output, provider error text, endpoints, and credentials are forbidden.

**Amendment (M5.6 read-only system-use view, 2026-08-04):** the authorization origin adds one
principal-only, access-logged `GET /system-use-decision` route and a fixed console projection. It exposes
currentness, exact configuration binding, bounded evidence depth/provenance/limitations, hard-condition
results, validity, and accountability-role availability. It exposes no evidence pack, rationale detail,
mutation control, trust badge, aggregate score, certification, or action-authority result and inherits the
console's strict self-only CSP, `frame-ancestors 'none'`, no third-party code, no cookies, and no CORS.

**Amendment (M5.7 headless selection protocol, reviewed at `442397a`, 2026-08-05):** authorization adds one fixed current
selection read, one boot-bound single-use card-evidence check, and one append-only case selection transition for
`proc:orchestrator`. All are Origin-guarded, access-recorded, and non-authorizing; the writes are strict-body.
The select operation can consume only an exact current check and is monotonically authority-narrowing: it may
invalidate and release unresolved work, but cannot issue authority, change the mandate's approved set, or return
a ruling, nonce, reservation, token, or output. Browser selection and native provider ingress remain closed.

**Implemented and reviewed (M5.8 browser-initiated selection, definition `85fef1f`, implementation `ff9e438`,
2026-08-06):** ADR-010 gives the orchestrator origin a
dynamic-session-only current-selection mirror and two-step preparation/selection protocol. The browser supplies
only an exact public target and then an unrelated preparation id; authorization check ids, the predecessor used
for selection, and gate bindings stay server-held. Mutations require a present exact same Origin. Calls to
authorization keep `proc:orchestrator` as the authenticated actor and record the server-derived case role/session
only as `claimed_actor`, never as authority. Provider ingress, `/messages`, and output release remain closed.

**Implemented and reviewed (M5.9 native provider ingress; definition `2a508ba`, correction `be01667`,
implementation `e58d397`, 2026-08-07):** ADR-011 adds an orchestrator-origin,
dynamic-session-only preparation/use/status protocol for one selected-lane call over authorization's existing
synthetic projection. The browser supplies no message, prompt, turn/model/selection binding, or retry instruction;
use is single and marked consuming before any dependency call. The native orchestrator receives the two provider
configurations and keys as its exclusive child-environment custody, reuses only the existing non-authorizing
call-begin, output-admission, and failure routes, and returns metadata-only disclosure status. `/messages`, output
release, conversation ingestion, and every authority-bearing route remain closed.

**Implementation candidate amendment (M5.10 conversation ingestion and output release):** ADR-012 activates a message-bound
two-step browser turn, authorization-owned `said` ingestion, an admission-issued single-use output release, and an
authorization-produced transcript. The orchestrator transports raw content only between the exact case session,
selected provider, quarantine, and authorization conversation store; it cannot assign tags/provenance, promote
model text beyond `inferred`, or call an authority-changing endpoint. Handoff redemption binds a server-generated
orchestrator session id into authorization-owned, maximum-15-minute provenance so caller headers cannot invent the
`said` item's actor. Projection-only M5.9 calls remain sealed.

**Implemented and reviewed at `8364745` (M5.11 governed proposal intake):** ADR-013 adds the dynamic-session
browser routes
`POST /cases/{case_id}/proposal-preparations`, `POST /cases/{case_id}/proposals`, and
`GET /cases/{case_id}/proposal-runs/{proposal_run_id}`. Authorization adds process-only intake consume/status and
case/run-status routes plus proposal precommit POST/status routes. All five accept only `proc:orchestrator`, are
Origin-guarded and access-recorded, and expose strict projections. Intake consume and all three reads are
`authorityChanging: false`; the precommit POST is `authorityChanging: true`, matching `proposal.submit`, because
it can issue Authorize/Submit/Verify rulings and open an escalation. That classification does not let the
orchestrator decide a ruling or reach Commit, reservation, token, service, or effect paths.

**M5.12 implementation candidate (native dialogue continuation):** reviewed ADR-014 adds one dynamic-session browser mutation and
one matching process route:
`POST /cases/{case_id}/proposal-runs/{source_proposal_run_id}/revision-preparations`. The browser body and process
body are strictly empty. Authorization alone resolves the exact disposed dialogue response, source proposal/action,
next revision, refreshed conversation, current model/governance bindings, and generated revision-run id. The process
route accepts only `proc:orchestrator`, is `authorityChanging: false`, Origin-guarded, and access-recorded. Existing
proposal use/status, model-call, intake, and precommit routes carry the later revision; no route accepts a
caller-carried response, proposal, gate, or successor.

## Context

Three OS processes make "the model proposes, a component outside the model decides, the executing service
verifies again" a process boundary rather than a comment. Static per-role tokens (principal, case officer,
applicant) stay at the authorization origin, per-process credentials authenticate inter-process calls, and
an ephemeral handoff creates the case officer's browser session at the orchestrator origin. Every decision
records the authenticated role. The boundary that matters: **the orchestrator can reach no authority-changing
endpoint**; the dedicated redemption route changes only one-time protocol-credential state and cannot affect
a mandate, ruling, escalation, commitment, effect, or dialogue answer. The orchestrator can neither read a
person's authorization-service credential nor forge a confirmation. This is demo-grade authentication by
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

The base role and process credentials are opaque static bearer tokens of 32 random bytes, hex-encoded,
generated once by a tooling script and written to the gitignored `.env.local`:

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

`ORCHESTRATOR_TOKEN_CASE_OFFICER` is retained only for the synthetic headless
`POST /w/{world_id}/actions/execute` seam. Browser case routes do not accept it, and neither the supervisor
nor the orchestrator exposes it through HTML, JavaScript, a response, storage, a log, or a record. The
browser protocol introduces no new static environment secret:

| Credential | Material and lifetime | Custody |
|---|---|---|
| Case-session handoff code | At least 32 cryptographically random bytes; single use; maximum 30 seconds; bound to handoff id, role, world, case, exact orchestrator origin, and authorization boot id | Raw value exists only in the authorization-origin browser, the exact-window message, the orchestrator browser/request, and the authenticated redemption call; authorization persists only its SHA-256 digest and lifecycle metadata |
| Case-session bearer | Independent random value of at least 32 bytes; one case and role; maximum 15 minutes; no refresh | Raw value is returned once to the orchestrator-origin browser and kept only in that origin's `sessionStorage`; the orchestrator keeps only its digest and bindings in process memory |

- Transport: `Authorization: Bearer <token>` on every authenticated call. The one-time handoff code is
  the credential in the strict same-origin redemption body, never a bearer and never a URL component. No cookies anywhere — which also means no
  CSRF surface on the data routes: there is no ambient credential for a cross-site form to ride, a
  foreign origin cannot read another origin's `localStorage`, and it cannot make the browser attach an
  `Authorization` header (ADR-004 completes the dialogue-control side).
- Loading: `node --env-file=.env.local` (Node ≥ 20.6, no dependency). **Startup validation, fail closed:**
  every required variable present, ≥ 64 hex chars, and all values mutually distinct. Two roles sharing a
  token would silently collapse the ACL, so a duplicate is a startup error.
- Verification: constant-time compare (`crypto.timingSafeEqual` after a length check).
- **Credentials never appear in logs, records, error bodies, or console output.** Only the resolved label
  (`role:principal`, `proc:orchestrator`, or the bounded case-session actor), handoff/session id, digest,
  bindings, and lifecycle state may be logged or recorded — never a raw value or prefix.

### 3. Who may call what — deny-by-default route ACL

A static table in the authorization service maps route → allowed credential labels. **A route with no ACL
entry is denied to everyone**, so adding a route without a decision fails closed. A startup assertion
enumerates registered routes against the table and refuses to serve on a mismatch.

Authorization service, all data routes under `/w/{world_id}/…`:

| Route | Allowed |
|---|---|
| `POST /proposals` (submit frozen proposal → ruling) | `proc:orchestrator` |
| `POST /proposal-intakes/{proposal_intake_id}/consume` (freeze one admitted draft) | `proc:orchestrator` only; `authorityChanging: false`, Origin-guarded, and access-recorded |
| `GET /proposal-intakes/{proposal_intake_id}` (content-free intake status) | `proc:orchestrator` only; `authorityChanging: false`, Origin-guarded, and access-recorded |
| `GET /cases/{case_id}/proposal-runs/{proposal_run_id}` (content-free proposal-run recovery) | `proc:orchestrator` only; `authorityChanging: false`, Origin-guarded, and access-recorded |
| `POST /cases/{case_id}/proposal-runs/{source_proposal_run_id}/revision-preparations` (M5.12 candidate: issue one dialogue-bound native revision preparation) | `proc:orchestrator` only; `authorityChanging: false`, Origin-guarded, and access-recorded |
| `POST /proposals/{proposal_id}/precommit` (fixed Authorize → Submit → Verify) | `proc:orchestrator` only; `authorityChanging: true`, Origin-guarded, and access-recorded |
| `GET /proposals/{proposal_id}/precommit` (read-only precommit recovery) | `proc:orchestrator` only; `authorityChanging: false`, Origin-guarded, and access-recorded |
| `POST /model-calls/begin` (durably bind one attempt, then return its authorization-resolved projection) | `proc:orchestrator` only; non-authorizing, Origin-guarded, and access-recorded |
| `POST /model-outputs/admit` (consume the call reference and classify one bounded model result) | `proc:orchestrator` only; non-authorizing, Origin-guarded, and access-recorded |
| `POST /model-calls/failures` (consume the call reference with fixed failure metadata) | `proc:orchestrator` only; non-authorizing, Origin-guarded, and access-recorded |
| `GET /cases/{case_id}/model-selection` (current selection and latest confirmed observation) | `proc:orchestrator` only; non-authorizing, Origin-guarded, and access-recorded |
| `POST /cases/{case_id}/model-selection-checks` (resolve one exact card-evidence check) | `proc:orchestrator` only; non-authorizing, Origin-guarded, access-recorded, maximum five-minute boot-bound reference |
| `POST /cases/{case_id}/model-selections` (consume a check and append the current selection) | `proc:orchestrator` only; non-authorizing, Origin-guarded, and access-recorded |
| `GET /rulings/{id}` (status projection, §7) | `proc:orchestrator` (own submissions), `proc:services_host` |
| `GET /mandates/{id}/approved-models` (picker and principal card-evidence source, card-verified) | `proc:orchestrator`, `role:principal`, `role:case_officer` |
| `POST /case-session-handoffs` (mint; adapter `authorityChanging: true`, `originGuarded: true`) | **`role:case_officer` only** |
| `POST /case-session-handoffs/{id}/redeem` (consume; adapter `authorityChanging: false`, `originGuarded: true`) | **`proc:orchestrator` only** |
| `POST /case-sessions/{session_id}/close` (expire authorization provenance and issued revision preparations; adapter `authorityChanging: false`, `originGuarded: true`) | **`proc:orchestrator` only**, exact on-behalf-of session |
| `POST /commit-verify` | **`proc:services_host` only** |
| `POST /effects/{effect_id}/outcome` | **`proc:services_host` only** |
| `POST /access-events` (narrow services-host denial evidence) | **`proc:services_host` only** |
| `POST /mandates` · `POST /mandates/{id}/amend` · `POST /mandates/{id}/revoke` | **`role:principal` only** |
| `GET /mandates` (read) | `role:principal`, `role:case_officer` (envelope they work under) |
| `GET /system-use-decision` (fixed read-only currentness/evidence projection) | **`role:principal` only**; access-recorded |
| `GET /escalations` (inbox) | `role:principal`, `role:case_officer` — each sees only escalations routed to it |
| `GET /escalations/{id}` (display mirror, §7 projection) | `proc:orchestrator` (read-only), `role:principal`, `role:case_officer`, and a routed `role:applicant` dialogue responder |
| `POST /escalations/{id}/disposition` | **the escalation's eligible role token only** |
| `POST /escalations/{id}/response` (dialogue answer) | **the routed conversation partner's role token only** (ADR-004) |
| `POST /escalations/{id}/revision` (continue after narrow/modify) | **`proc:orchestrator` only** |
| `GET /records…` · `POST /records/verify` | `role:principal` (full), `role:case_officer` (case-scoped) |
| `GET /extract` (server-side scoped applicant extract) | **`role:applicant` only** |
| `POST /challenges` (append correction and open routing obligation) | **`role:applicant` only** |
| `GET /console/runtime-config.json` (exact configured origins only) | unauthenticated static data, no credentials |
| `GET /console/*` (governance console assets) | unauthenticated static assets, no data |
| `GET /healthz` | unauthenticated, no world, no data |

The mint request is a strict `{case_id}` body under the authorization-origin case-officer bearer. Role,
world, exact configured orchestrator origin, and current authorization boot id are server-owned bindings,
not caller-selected fields. Mint is conservatively marked `authorityChanging: true` because it changes
durable handoff state and is browser-facing, so ADR-002's present-but-foreign-Origin guard applies. The
redemption route is server-to-server protocol-authentication plumbing: it atomically consumes the exact
credential state but cannot mint a handoff or change a mandate, ruling, escalation, commitment, or effect,
so `authorityChanging: false` is an explicit classification rather than an omission. It nevertheless carries
the independent `originGuarded: true` transport flag and rejects a present foreign or opaque origin. Existing
authority-changing routes imply that guard; the handoff implementation makes the two concepts explicit so
protocol-credential mutation is not mislabeled as action authority. Explicit session close likewise expires only the
authorization-owned provenance receipt and invalidates any still-issued revision preparation for that session; it
cannot change action authority. All three transitions are durably appended
before their response. The exact config route precedes the wildcard console shell and
returns only `{authorization_origin, orchestrator_origin}` with `Cache-Control: no-store`, no CORS, and no
caller-supplied override.

ADR-013's intake consume follows the redemption classification: it freezes evidence and advances protocol state
but changes no mandate, ruling, escalation, commitment, or effect, so all three intake routes are explicitly
`authorityChanging: false`. The precommit POST instead follows `proposal.submit`: issuing a ruling or opening an
escalation is a durable authority-record mutation and is conservatively `authorityChanging: true`, even though
authorization alone decides the outcome and the operation cannot Commit or execute. Its companion status GET is
read-only and `authorityChanging: false`. The independent `originGuarded: true` flag applies to all five routes.

ADR-014's revision-preparation POST follows the same protocol-state classification as model-selection checks and
proposal intake: it can issue, expire, invalidate, or consume only a short-lived continuation binding. It cannot
change an escalation disposition, issue a ruling, claim a successor, Commit, or execute. It is therefore
`authorityChanging: false` but retains the independent Origin guard and bounded access evidence. Exact retries under
the same session/source/currentness tuple return the same issued preparation rather than multiplying state.

Orchestrator: exact `GET /console/runtime-config.json` and the remaining `GET /console/*` serve the same
no-store origin projection and unauthenticated fixed assets, respectively; the exact route precedes the
wildcard shell. `POST /w/{w}/case-sessions/redeem`
accepts only the single-use handoff in a strict same-origin body and is explicitly
`authorityChanging: false, originGuarded: true`: it creates authentication state but no action authority.
`POST /w/{w}/cases/{id}/message-preparations`, `POST /w/{w}/cases/{id}/messages`,
`GET /w/{w}/cases/{id}/conversation`, `GET /w/{w}/cases/{id}/state`, `GET /w/{w}/models`,
`GET /w/{w}/cases/{id}/model-selection`,
`POST /w/{w}/cases/{id}/model-selection-preparations`,
`POST /w/{w}/cases/{id}/model-selections`,
`POST /w/{w}/cases/{id}/model-turn-preparations`,
`POST /w/{w}/cases/{id}/model-turns`, `GET /w/{w}/cases/{id}/model-turns/{turn_id}`,
`POST /w/{w}/cases/{id}/proposal-preparations`, `POST /w/{w}/cases/{id}/proposals`,
`POST /w/{w}/cases/{id}/proposal-runs/{source_proposal_run_id}/revision-preparations` (defined by ADR-014),
`GET /w/{w}/cases/{id}/proposal-runs/{proposal_run_id}`,
and `POST /w/{w}/case-sessions/close` require the
dynamic case-session bearer and re-check its exact role/world/case/expiry binding. ADR-010's two selection
mutations, ADR-011's two model-turn mutations, ADR-012's two message mutations, and ADR-013's two proposal
mutations, plus ADR-014's revision-preparation mutation, additionally require a present exact orchestrator Origin;
all other browser routes continue to reject a present foreign or opaque Origin. The
bounded headless
transport seam `POST /w/{w}/actions/execute` continues to accept only the derived
`ORCHESTRATOR_TOKEN_CASE_OFFICER`; browser sessions are denied there, and the static derived credential is
denied on every browser case route.
Services host: `POST /w/{w}/services/{service}/execute` `proc:orchestrator`;
`GET /w/{w}/effects/{idempotency_key}` (read-only reconciliation probe) and
`GET /w/{w}/registry-records/{record_id}` (immutable synthetic evidence resolution) `proc:authz`;
`GET /healthz` open. The orchestrator is explicitly denied on both authorization-facing reads.
`commit-verify`, effect outcomes, and reconciliation probes carry both the current services-host boot id
and the persistent services-ledger id; only absence under the same ledger id can release a commitment.

**The reviewed M5.11 implementation exposes the orchestrator's process credential on exactly twenty gate/data
routes plus dedicated case-session-handoff redemption and close routes. The M5.12 candidate adds one gate/data route,
making exactly twenty-one.** The resulting twenty-one are proposal submission, proposal-intake consumption,
proposal-intake status, proposal-run status, proposal precommit, proposal-precommit status, model-call begin,
model-output admission, model-call failure, conversation-message ingestion, model-output-release consumption,
model-output-release status, conversation read,
model-selection read, model-selection check, model selection, dialogue-revision preparation,
revised-proposal continuation, ruling read,
approved-model read, and the read-only escalation mirror ADR-004
§7 requires. Redemption
returns only `{handoff_id, role, world_id, case_id, target_origin, authorization_boot_id, consumed_at}`
after atomic consumption; it is an
authentication claim, not a ruling or authorization. Nothing else changes: the process credential is
denied on handoff mint, mandate grant/amend/revoke, escalation disposition, dialogue response,
`commit-verify`, effect outcome, record read, verify, and extract. Reading escalation state and redeeming
an already issued handoff are not authority-changing, and their projections are fixed. The orchestrator
also never receives a commit token: the services host obtains its own from `commit-verify` and never trusts
the orchestrator's claim of approval.

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
nor carries the answer, so it can neither read the token nor forge a confirmation or a permission. A
redeemed case-session claim may identify the chat seat for display and provenance, but it remains
`claimed_actor` at the authorization boundary and never substitutes for the person's role token.

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

The headless `ORCHESTRATOR_TOKEN_CASE_OFFICER` remains sufficient only for synthetic HTTP tests. It is not
the parent credential of a browser session and never crosses a process response. Browser case routes accept
only the independent dynamic session below.

Token custody in the browser is demo-grade and explicit: a token-entry field on the governance origin,
held in that origin's `localStorage` (not `sessionStorage` — ADR-004's deep link opens a new tab, which
would start empty), sent as a bearer header. No login, no session exchange, no cookie.

The static console has no inline executable content and no third-party dependency. Its external module and
stylesheet are same-origin resources; its browser fetches use relative paths, omit cookies, and keep token
values out of URLs, rendered output, and error messages. The principal surface calls only mandate,
approved-card, system-use-decision, routed-escalation, and record routes already owned by this service. The applicant surface
calls only the server-side scoped-extract route. UI disposition controls are intersected with the general
disposition vocabulary and appear only while the returned contract is open; the endpoint remains the
  authority and can still refuse a stale or forged request. The dialogue deep-link surface intersects the
  returned contract with the closed dialogue vocabulary and posts directly to the authorization service;
  wrong-role, out-of-contract, unresolved-evidence, foreign-Origin, and terminal-replay cases remain
  endpoint refusals, not UI decisions.

#### 5.1 Authorization-origin handoff to the orchestrator-origin case session

Both consoles first read their same-origin `GET /console/runtime-config.json` projection and require the
origin corresponding to the current page to equal `window.location.origin`. This is how each side learns the
other exact configured origin without a URL parameter, hard-coded port, inline executable configuration, or
caller-selected target.

1. **Mint on the credential-bearing origin.** A user-initiated governance-console control posts strict
   `{case_id}` JSON to `POST /w/{world_id}/case-session-handoffs` with `AUTHZ_TOKEN_CASE_OFFICER`. Before the
   asynchronous mint, the click handler installs its single-use message listener and opens the fixed child
   synchronously; a blocked or wrong-origin window aborts without minting. The
   authorization service verifies that the synthetic case exists in that token's world, generates the
   handoff id and at-least-256-bit code, and binds the case-officer role, world, case, configured
   orchestrator origin, current authorization boot id, creation time, and a deadline no more than 30 seconds
   later. Under the world mutex it appends `issued` state containing the SHA-256 code digest but not the raw
   code; the response is returned only after that append and carries `Cache-Control: no-store`.
2. **Transfer to one exact window.** The console opens `${ORCHESTRATOR_ORIGIN}/console/handoff` with no
   query, fragment, world, case, handoff id, or credential in the URL. The child sends a typed readiness
   message to the configured authorization origin. The parent accepts it only when both `event.origin` and
   `event.source` match the expected origin and returned `WindowProxy`, then transfers the strict handoff
   object with the exact orchestrator `targetOrigin`. The child performs the reciprocal origin/source check,
   each side removes its single-use listener, the child verifies the transferred target origin equals
   `window.location.origin`, receives the value only into memory, and sets `window.opener = null`.
   Unlike ADR-004's ordinary dialogue link, this one user gesture deliberately uses a transient opener; the
   exact-window checks and immediate severing are part of the protocol, not optional UI hardening.
3. **Redeem over both authenticated boundaries.** The child posts the strict object to its own
   `POST /w/{world_id}/case-sessions/redeem`. That handler rejects a present foreign or opaque `Origin`,
   hashes the code, and calls the authorization service's
   `POST /w/{world_id}/case-session-handoffs/{handoff_id}/redeem` with
   `AUTHZ_TOKEN_PROC_ORCHESTRATOR`. Under the authorization world's serialization point, redemption succeeds
   only for one exact, still-`issued`, unexpired match across digest, role, world, case, configured origin,
   and current boot id, and changes it atomically to `consumed`. A crash after consumption yields no session;
   the user must mint again. On startup, prior-boot `issued` handoffs are expired before the listener binds.
4. **Create an independent session.** Only after the bounded claim returns does the orchestrator generate
   an unrelated at-least-256-bit bearer, store its digest with role/world/case/creation/expiry and
   `active` state in process memory, and return the raw value once with `Cache-Control: no-store`. The browser
   stores it only in orchestrator-origin `sessionStorage` and sends it only as a same-origin bearer. The
   session lasts no more than 15 minutes and has no refresh or widening operation. Explicit logout first closes the
   exact authorization-owned provenance receipt through the process-authenticated backchannel, then closes the
   orchestrator-local bearer and quarantined state. Tab close removes the client copy; expiry or an orchestrator restart removes server
   usability. A fresh authorization-origin handoff is the only way to create another session.

Both origins serve these surfaces with a strict self-only CSP, `frame-ancestors 'none'`, no third-party
browser code, no cookies, and no CORS. Extra payload fields, missing process authentication, a binding
mismatch, expiry, replay, concurrent double redemption, a prior boot id, an unknown session, or use of a
handoff/session credential on an authority-bearing route fails closed. External refusal bodies stay fixed;
the durable internal evidence may name the reason, authenticated actor, ids, digests, bindings, and state,
but never raw credentials.

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
  ADR-003's checkpoint example) and every static, derived, handoff, and session credential is scoped to it; a token presented against
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
- proposal-intake consumption → the idempotent content-free proposal/intake result carrying proposal/run ids,
  terminal intake state, proposal hash, and recorded time. Intake status returns the same bounded lifecycle
  metadata; neither returns draft content, store items, raw parse errors, prompt, or model output;
- proposal-run status → the bounded process recovery binding needed to locate durable intake/proposal/precommit
  progress without returning the private intake id or content;
- dialogue-revision preparation → issued/consumed/expired/invalidated state, source and generated run ids, expiry,
  and bounded currentness result; no dialogue item, question, answer/evidence, source hash, response record, action
  lineage, projection, or authority binding;
- proposal precommit → the fixed Authorize/Submit/Verify progress and each gate's ruling projection. The read-only
  status returns only durably recorded progress; neither route exposes evidence refs, rationale, nonce,
  reservation, commit token, credential, or executable capability;
- ruling → `{ruling_id, verdict, ux_class, reason, status, successor_ruling_id, validity_window}`;
- model-call begin → `{call, projection}` where `call` is the durable metadata-only open lifecycle binding and
  `projection` contains `{world_id, case_id, provider, role: "acting", items, summary}`. The case and role are
  authorization-owned and `summary` names exact included/dropped counts, dropped ids, and unmet tags;
- model-output admission → `{kind: "model_call_admission", call_id, decision}` where `decision` contains
  `{kind, disposition: admitted | withheld, authority_effect: "none", case_id,
  turn_id, mandate/card/model references, projection_digest, projection_item_count, output_digest,
  model_resolution, flags, reasons, derived_tags?}`. A withheld result omits derived tags; neither result
  contains model text, a ruling, a nonce, or a token. The same fixed decision metadata is appended to the
  access chain before return;
- model-call failure → the terminal lifecycle binding plus `failed`, the fixed reason, `possible | confirmed`
  provider-disclosure state, and nullable served-model id. It contains no raw response or error detail;
- conversation-message ingestion → the idempotent message/item ids, case conversation version, content digest,
  ingress-profile id/digest, byte length, and recorded time. Raw text and assigned store fields are omitted;
- model-output release consumption → the release/call/turn/item ids, consumed state, case conversation version,
  output digest, and recorded time. The process-only release status is the same bounded metadata without content;
- conversation read → the bounded ordered user/model transcript created by ADR-012, including text only on this
  dedicated content-bearing process route. Fixture/dialogue/internal store items, tags, release references,
  projections, and authority bindings are omitted;
- model-selection read → the current authorization boot id plus the current transition and its latest confirmed
  observation, or explicit unselected state. The boot id is process-only and is redacted from the orchestrator's
  browser mirror; the response exposes no check history, raw output, or authority-bearing object;
- model-selection check → one exact current card-evidence projection plus a boot-bound check reference carrying
  only case/mandate/target/card-key/system-use bindings, expected predecessor, issue time, and expiry;
- model selection → the append-only transition projection plus invalidated-ruling and terminalized-open-call
  counts. It states `authority_effect: "none"` and contains no prompt, model output, ruling, nonce, reservation,
  commit token, or credential;

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
  bounded system-use reference/current-at-record facts, and local-receipt projections for the single synthetic applicant world. It excludes evidence payloads,
  bindings, nonces, reservations, idempotency keys, and full internal records.
- system-use decision → principal-only fixed currentness, exact configuration binding, evidence
  type/provenance/depth/as-of/limitations, hard-condition results, validity/redecision triggers, bounded
  basis/unresolved-finding facts, and accountability-role availability. It excludes evidence refs and packs,
  detailed rationale, prompts, outputs, credentials, badges, scores, certifications, and mutation controls;

A later provider/browser ingress may release only the exact response bytes whose recomputed `model-output`
digest equals the retained `admitted` decision for that turn; `withheld` terminates the turn. The M5.3 slice
does not yet implement that release path, so the admission result cannot be bypassed by an active browser route.

The strict challenge body is `{action_id, contested_entry_id, correction_text}`. Authorization verifies that
the record belongs to the named action, rejects a duplicate open challenge, appends rather than edits, and
returns only the new record and obligation ids. The projected challenge names the correction, contested entry,
`withdrawn-pending-review` reliance state, and principal recovery owner. Resolution remains outside this M4
mechanism because no independent remedy decider exists in the POC.

The orchestrator-facing ruling, model, and escalation-status projections carry neither record content nor
applicant extract data.

Every route in the record family (`/records…`, `/records/verify`, `/extract`) appends an entry to the
**access-log chain** before returning, so verification never mutates the chain it verifies, and the
applicant's extract is assembled server-side in the authorization service — never in the orchestrator.
Escalation-status polls read state rather than record entries and are deliberately not access-logged
(ADR-004 §7), or polling would drown the chain.

### 8. Declared limits (demo-grade, stated in the README)

Static base and derived tokens have **no rotation, no expiry, and no revocation** short of editing
`.env.local` and restarting; only handoff codes and dynamic case sessions carry the short expiries above.
All three processes run as one OS user on one machine, so there is no OS-level isolation behind the process
boundary. A bearer token in either origin's browser storage is readable by any script on that origin —
tolerable only because both origins serve no third-party content and ship a strict CSP. The handoff's
transient cross-origin opener is an additional declared POC cost.
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
The M5.2 listener/process coverage additionally proves that non-orchestrator credentials receive 403,
caller-added scope fields receive 422, the configured case and acting role are injected, and every successful
or refused projection disclosure is represented in the access chain.
M5.3 coverage proves that foreign Origin and non-orchestrator calls are refused before evaluation; caller-added
case or tag scope is rejected; stale projection or authority evidence fails closed; served-model substitution
and the deterministic feelings/dependency red lines withhold; and raw admitted or rejected text appears in
neither response nor access record. The case-message route remains `501`, making the not-yet-implemented
digest-to-release binding unreachable rather than silently optional.

**Required with M5.7 implementation.** Real-listener tests must prove all three selection routes reject every
non-orchestrator credential and foreign Origin, accept no caller-supplied mandate/card-currentness/system-use or
served-model fact, consume a check once, enforce exact case/predecessor/expiry bindings, and access-record success
and refusal without output or credentials. The existing negative-authorization enumeration must include all
three routes; the caller-facing model-call failure route must reject the authorization-owned
`selection-invalidated` reason, while the browser message route remains `501`.

**Required with the M5.8 implementation.** Real-listener tests must prove the three orchestrator-origin
selection routes accept only an exact active dynamic case session; both mutations reject absent, foreign, and
opaque Origin; static, role, process, handoff, expired, closed, wrong-world, and wrong-case credentials fail; strict
bodies cannot assert check/predecessor/session/actor/authority facts; and browser responses omit hidden
authorization bindings. The orchestrator must derive on-behalf-of headers from its session record, burn local
preparations on replay/expiry/restart or dependency ambiguity, recover current selection from authorization, and
leave provider ingress, conversation ingestion, output release, and `/messages` closed.

**Required with the M5.9 implementation.** Real-listener tests must prove the three orchestrator-origin model-turn
routes accept only the exact dynamic case session; both mutations reject absent, foreign, and opaque Origin; and
strict bodies cannot assert message, prompt, turn, selection, model, mandate, system-use, projection, tag, actor,
provider, authority, or retry facts. Provider credentials/configuration must appear only in the orchestrator child
environment and never in output or records. The process-only current-selection projection must carry the
authorization boot id while its browser mirror redacts it, so a restart invalidates the session before call-open.
Synthetic loopback coverage must show server-derived claimed-session provenance, consuming-before-call, selection
race closure under a shared case-local selection/turn mutex, predecessor/session cleanup with honest `discarded`
status, no automatic retry/fallback, branch-derived disclosure status, content-free responses, sealed quarantine,
and the still-closed `/messages`, conversation-ingestion, release, and M6 paths.

**Required with the M5.10 implementation.** Real-listener tests must prove exact session, path and Origin
confinement for message preparation/use and transcript reads, and exact `proc:orchestrator` confinement for the
four new authorization routes. Strict bodies cannot assert store, origin actor, tags, provenance, clearance,
conversation version, model/currentness facts, release binding, authority, or retry. The authorization adapter's
complete route matrix must deny the orchestrator every authority-changing route while access-recording bounded
metadata for allowed ingestion/release/read operations. Browser schemas must be constructed field-by-field and
exact-key tested so release ids, boot ids, tags, item ids, projections, and authority bindings never cross origins.
Redemption/session tests must prove that message attribution resolves from the authorization-owned handoff receipt,
not caller headers, and that mismatch, expiry, or a prior boot fails before storage.

**Required with the M5.11 implementation.** Real-listener tests must prove the three orchestrator-origin proposal
routes accept only the exact active dynamic case session; both browser mutations reject absent, foreign, and opaque
Origin; and strict bodies cannot assert proposal/evidence content, schema/prompt, model/currentness, authority,
gate, service/action class, or retry facts. The five authorization routes must accept only `proc:orchestrator`,
reject present foreign/opaque Origin, and append bounded access evidence for success and refusal. Route-table tests
must assert intake consume and all three reads are `authorityChanging: false`, while the precommit POST alone is
`authorityChanging: true` and still permits no caller-selected gate, Commit, reservation, token, service, or
effect. Intake ambiguity, single-use consumption, restart recovery by proposal-run id, exact-key browser/process
projections, and fixed Authorize → Submit → Verify ordering must be covered without exposing content or private
bindings. Existing dynamic sessions remain denied on the headless action-execution route.

**Required for the M5.12 implementation candidate.** Real-listener tests must prove the new browser route accepts only
the exact active case-officer session and present exact Origin, while the authorization route accepts only
`proc:orchestrator`, rejects present foreign/opaque Origin, and appends bounded access evidence. Both strict empty
bodies must reject response/proposal content, item/scope, question/contract, source action/revision, model/currentness,
authority, gate, retry, and successor facts. Route-table tests must assert the process route is
`authorityChanging: false` and that the only authority-changing M5.11/M5.12 process mutation remains precommit.
Exact retry, single use, TTL, invalidation, restart, same-case recovery, case mutex ordering, and exact-key
projections must be covered without exposing dialogue or authority internals. Existing proposal use/status and
precommit routes remain the only dynamic path after preparation; Commit/effect and the headless continuation route
stay closed to the browser.

**Required with the browser handoff implementation.** Real-listener tests cover exact-origin/exact-window
message acceptance and wrong/opaque origin or wrong-window refusal; mint-role confinement; absence from URLs,
storage other than the named `sessionStorage`, responses after the one-time returns, logs, records, errors,
and console output; exact role/world/case/origin/boot binding; expiry; concurrent double redemption; replay;
authorization restart after issue; orchestrator restart after session creation; logout; rejection of the
headless derived credential on browser routes; rejection of the dynamic session and handoff on every
authority-bearing route; and unchanged negative authorization across all other orchestrator-accessible paths.

**Deferred, by decision.** No rotation, expiry, refresh, or revocation list for the static base credentials.
The handoff and session expiries above do not add a general identity/session service. No mTLS or signed
inter-process requests — the process credential is a shared secret, and a local attacker who can read
`.env.local` has everything. No per-user identity, directory, or audit of *who* holds a role token. No
general authenticated rate limiting beyond the body cap and the bounded unauthenticated-ingress control
above. The v1.1 sandbox still needs a world-scoped base-token minting path and a world lifecycle
(create, expire, delete); this ADR reserves the seam and specifies nothing further.
Authenticated 403s remain one durable transaction per attempt by design. The unauthenticated limiter is
global per process, so one flooder can suppress detailed evidence for peers during the short window; this
avoids an attacker-controlled, unbounded per-peer key map.

**Implementation follow-up.** `.env.local.example` must gain the six token variables, `RUNTIME_HOST`,
`DEMO_WORLD_ID`, and the three port variables — alongside ADR-007's `GATE_HMAC_KEY` /
`GATE_HMAC_KEY_ID` — before M2; this ADR does not change that file.
