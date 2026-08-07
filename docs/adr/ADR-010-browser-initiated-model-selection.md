<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-010 — Browser-initiated governed model selection

**Status:** definition accepted at `85fef1f`; bounded implementation `ff9e438` passed exact-SHA adversarial review
with GO — no findings (2026-08-06).
**Spec:** §3 (case console and demo authentication), §5 (model navigation and **find → check → use**),
§7 beats 19–21, and §10 M4–M5.

## Context

ADR-009, implemented and reviewed at `442397a`, makes the current acting-model selection
authorization-owned, append-only, replayable, predecessor-bound, and single-use-check-bound. Its three process
routes deliberately have no native caller. The case console already has ADR-002's short-lived dynamic
case-session bearer and a read-only plural model/card projection, but its local **Prepare this model** button only
writes a requested id to `sessionStorage`; it cannot change authorization state and proves no fresh check.

The remaining browser boundary must make selection a case-officer-initiated case act without turning the browser,
the model, or an orchestrator assertion into action authority. The principal still owns the approved set and
default through the mandate. Authorization still decides whether an initial selection or switch is valid and
retires prior-lane work atomically. This slice adds no model call, provider ingress, conversation ingestion,
output release, empathy transition, action ruling, or M6 capture path.

## Decision

### 1. The orchestrator origin owns the browser gesture; authorization owns the transition

The case officer acts only through the fixed orchestrator-origin case console under the existing dynamic session
bearer. Three routes expose a bounded browser protocol at that origin:

```text
GET  /w/{world_id}/cases/{case_id}/model-selection
POST /w/{world_id}/cases/{case_id}/model-selection-preparations
POST /w/{world_id}/cases/{case_id}/model-selections
```

All three require an active session whose server-owned role/world/case bindings exactly match the path. The static
derived headless case-officer credential, authorization-service role tokens, handoff code, process credentials,
and a session for another case are refused. They use no cookies and emit no CORS headers. A present foreign or
opaque Origin is refused on every route; both mutations additionally require a present Origin exactly equal to
the orchestrator origin. This is a same-origin browser seam, not a general raw-client API.

The orchestrator calls only ADR-009's already reviewed process-authenticated current-read, check, and select
routes. The browser never receives an authorization-service credential, authorization check id, card digest,
verifying-key id, system-use binding, policy binding, nonce, reservation, ruling, commit token, prompt, or model
output. It cannot supply the predecessor used by authorization. The model has no route or credential with which
to initiate a selection.

Selection remains `authority_effect: none`. The dynamic session authenticates the case seat but grants no action
authority; a successful transition can only choose within the principal-approved set and retire unresolved work.
Every later provider disclosure and consequential effect still requires the M5.5–M5.7 model-call and gate
bindings, including commitment verification.

### 2. Find stays plural; check creates a browser preparation

The existing session-authenticated `GET /w/{world_id}/models` remains the plural **find** view. It exposes the
mandate's explicit default and factual signed-card evidence without a score, recommendation, certification,
legal approval, or green-light result.

The preparation request is strict and carries only one exact target:

```json
{
  "target": {
    "card_id": "publicai-apertus-v1.5-70b",
    "card_version": 1,
    "requested_id": "swiss-ai/apertus-v1.5-70b"
  }
}
```

The orchestrator derives the current selection from authorization, never from DOM state, `sessionStorage`, card
order, or request fields. It then asks authorization for an ADR-009 check using that exact predecessor and target.
Only after authorization has appended the check does the orchestrator create an independent browser preparation
and return:

```text
{preparation: {preparation_id, target, issued_at, expires_at},
 evidence: <the exact refreshed single-card evidence projection>}
```

The browser preparation id is at least 128 bits of fresh randomness and is correlation metadata usable only with
the same active case-session bearer. It is unrelated to the hidden authorization check id. The orchestrator keeps
the mapping in process memory and binds it to the session id, role, world, case, exact target, exact predecessor,
authorization boot id, hidden check id, issue time, and expiry.

The browser preparation lasts at most **two minutes** from the refreshed evidence response and is additionally
capped by both the case-session expiry and authorization check expiry. This is the browser gesture window, chosen
explicitly rather than inheriting ADR-009's five-minute headless ceiling. A person who needs longer requests a
fresh preparation and receives freshly resolved evidence. At most one preparation is issued per session: creating
a successor burns the prior local preparation. Session close/expiry, either process restarting, authorization-boot
mismatch, target change, or a current-selection refresh that reveals a changed predecessor burns it.

The implementation retains the handoff id and authorization boot id in the in-memory case-session record. A check
issued under a different authorization boot closes the old session and requires a fresh authorization-origin
handoff; it is never exposed or used. Orchestrator restart already destroys the session and all preparations.

### 3. Use consumes one preparation; the browser supplies no gate binding

After rendering the refreshed evidence, the console enables a separate user control to select that exact target.
The strict request carries only:

```json
{"preparation_id":"msp_…"}
```

The orchestrator authenticates the same session and atomically moves the preparation
`issued → consuming` before making the authorization call. It supplies the hidden check id and server-held
predecessor to ADR-009's select route. A second or concurrent use receives a conflict and cannot make a second
dependency call.

Success moves the preparation to `consumed`, discards its hidden mapping, clears every other local preparation for
the case, and returns only a browser-safe transition projection: selection id/kind/predecessor, mandate id/version,
the public target triple, selection time, `authority_effect: none`, and the counts of invalidated rulings and
terminalized open calls. The response omits the authorization check id, card/key digests, system-use reference,
and internal record payload.

A definite authorization refusal, malformed dependency response, timeout, connection failure, or lost response
burns the preparation; the orchestrator never retries selection automatically. The browser recovers by reading the
authoritative current-selection mirror and, if needed, starts a fresh preparation. If authorization committed the
transition before a response was lost, that read shows the new selection. If it did not, the predecessor is
unchanged. ADR-009's single-use check and world-lock transaction remain the final replay and race boundary.

Initial selection is still restricted by authorization to the mandate's explicit default. Later no-op selection,
unapproved target, stale predecessor, changed mandate/card/policy/system-use fact, expired or replayed check, and
ambiguous authority all fail closed. A → B → A creates three distinct selection identities and cannot revive an old
ruling. Endpoint outage or provider failure never chooses a fallback.

### 4. Current selection is a redacted authoritative mirror

The browser current-selection route asks authorization on every request and returns `unselected` or a bounded
selection projection. It may include the public target, transition identity/time, and latest confirmed
requested-versus-served observation. It excludes the authorization check id, card/key digests, system-use and
policy bindings, process actor, call reference, and access-record payload.

The console never treats a local prepared target as current. It marks a model current only from this mirror and
reloads it after every success, dependency ambiguity, or page-state refresh. No initial model is inferred from
array order or software configuration; before the first selection, the mandate default is labelled as the only
valid initial target but is not silently selected.

### 5. On-behalf-of data is provenance, not authority

For the authorization check and select calls, the orchestrator derives
`X-On-Behalf-Of-Role: case_officer` and `X-Session-Id` from the authenticated server-side session record. Neither
header is accepted from the browser request body or headers. ADR-002 records the authorization-service actor as
`proc:orchestrator` and the case seat as `claimed_actor`; both access events therefore retain bounded session
provenance and join through the authorization check/selection evidence.

The claim never participates in mandate, card, system-use, policy, predecessor, invalidation, ruling, or commit
decisions. It is not proof of civil identity or of cognitive review, and a compromised orchestrator remains inside
this demo-grade trust boundary. Anything requiring a person's own standing—dialogue response, permission,
mandate change, or escalation disposition—continues to require the person's authorization-origin role token and
cannot use this session claim.

### 6. Case-console behavior

The current local-only preparation marker and `runtime-case-model-choice` storage key are removed. A card's
**Review current evidence** control requests a server preparation and renders the returned refreshed evidence.
Only that response enables **Select this model for the case**; its preparation reference is held in document
memory rather than persistent or session storage. Loading another target, refreshing evidence, closing the
session, or any failed selection clears the control.

The UI labels the mandate default and current selection, presents effective data classes and known limits, and
states that selection creates no action authority and sends no model request. It never auto-selects, auto-falls
back, ranks models, or turns validity into a green-light surface. `/messages` remains `501` and
`model_interaction_available` remains false.

## Acceptance tests for the implementation tranche

- The three browser routes require the exact dynamic role/world/case session. Missing, expired, closed, foreign-
  case, static headless, role-token, process-token, and handoff credentials fail; mutation requests with absent,
  foreign, or opaque Origin fail. No browser-visible response, orchestrator log, URL, cookie, or browser storage
  contains a credential or hidden authorization check id; authorization's bounded access evidence retains the
  check/result correlation.
- Strict schemas reject caller-supplied predecessor, session id, actor, mandate/card digest, verifying key,
  system-use/policy fact, check id, served model, authority result, or extra field.
- Preparation derives current selection from authorization, returns the exact refreshed card-evidence projection,
  lasts no more than two minutes and no longer than its session or hidden check, and is bound to one session,
  case, target, predecessor, and authorization boot. Replacement, expiry, close, or restart burns it.
- Use is single and atomic locally. Missing, expired, replayed, foreign-session, target-swapped, and concurrent
  preparation uses make no second authorization call. A definite or ambiguous dependency failure burns the
  preparation and never triggers an automatic retry or fallback.
- Authorization receives only its existing strict check/select bodies plus server-derived on-behalf-of headers.
  Access evidence records `proc:orchestrator` separately from the claimed case-officer session, and the claim has no
  code path to grant authority or satisfy a role-token route.
- Initial selection can only be the mandate default. Approved A → B and B → A switches use fresh preparations,
  produce distinct durable ids, retire unresolved prior-lane work, survive authorization replay, and recover in
  the browser solely through the redacted current-selection read.
- A stale predecessor or a mandate/card/policy/system-use change between preparation and use fails closed. A switch
  racing a call or ruling retains ADR-009's mutex-ordered result, including late-output refusal and no revived
  authority.
- The browser projections omit hidden check ids and authorization-only bindings. The UI never infers current state,
  persists a target/preparation, ranks evidence, or claims assurance.
- Real-listener coverage proves the full ACL/Origin matrix, exact on-behalf-of derivation, redaction, two-session
  races, authorization restart, orchestrator restart, and that successful selection makes no provider request,
  creates no conversation item or released output, leaves `/messages` at `501`, and does not begin M6.

## Consequences and deferred work

The reviewed M5.8 implementation completes the case-officer browser initiation of governed selection and the
user-choice portion of beat
19. Beat 19 remains only partial until a native provider call under the new lane produces confirmed served-model
evidence and fresh Submit/Verify outcomes. Beats 20–21 retain their existing deterministic coverage; no live probe
or provider substitution test is added here.

ADR-011's bounded native provider ingress at `e58d397` passed exact-SHA adversarial review with no findings.
Still deferred to separately approved slices: admitted-output release and conversation ingestion,
empathy-trigger completion, general multi-case binding, live provider runs, and M6 capture. The M5.8
implementation may not run probes, generate or rotate keys, sign cards, edit generated/append-only production
records, or move the pinned Charter provenance.
