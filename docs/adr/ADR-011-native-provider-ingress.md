<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-011 — Native provider ingress to sealed quarantine

**Status:** proposed M5.9 definition; awaiting exact-SHA adversarial review.
**Spec:** §3 (orchestrator, model adapter, and case console), §4 (model-call and system-use bindings),
§5 (entry boundary, model selection, and fail-closed provider behavior), §7 beats 14 and 19–21, and §10 M5.

## Context

M5.5–M5.8 establish an authorization-owned model-call lifecycle, a current system-use prerequisite, governed
model selection, and a dynamic-session browser initiator. `ModelTurnCoordinator` already composes the call-begin,
provider, output-admission, and failure paths against synthetic loopback adapters, but the native orchestrator
process does not construct it. The supervisor withholds both model-lane credentials from every child, and the case
console's `/messages` route remains `501`.

The next boundary must prove that one case-officer gesture can activate the already governed selected lane without
opening a second selection path, letting browser input bypass authorization's projection, or treating an admitted
model result as releasable. Conversation ingestion and output release each need additional authority, provenance,
retry, and custody decisions. Combining either with provider ingress would make this slice too broad and would
blur whether a browser message actually reached the model.

M5.9 therefore runs the selected model only over the current authorization-produced synthetic case projection.
It accepts no chat text and releases no model bytes. Its browser control is labelled as a model run over the current
authorized projection, not as an active chat seat.

## Decision

### 1. A two-step case-session gesture starts one projection-bound run

The orchestrator origin adds three dynamic-session-only routes:

```text
POST /w/{world_id}/cases/{case_id}/model-turn-preparations
POST /w/{world_id}/cases/{case_id}/model-turns
GET  /w/{world_id}/cases/{case_id}/model-turns/{turn_id}
```

All three require the exact active case-officer session bound to the path's world and case. The static headless
credential, authorization-service role/process credentials, handoff values, foreign-case sessions, and expired or
closed sessions are refused. They use no cookies and emit no CORS headers. A present foreign or opaque Origin is
refused on every route; both POSTs require a present Origin exactly equal to the orchestrator origin.

Preparation has a strict empty body. The orchestrator reads authorization's current selection and refuses an
unselected case, a stale or malformed dependency response, an authorization boot id different from the session's
handoff binding, or a selection that does not map exactly to one locally configured
`{lane, card_id, card_version, requested_id}` tuple. M5.9 adds that boot id to the process-only current-selection
envelope; the existing browser mirror must continue to redact it. This lets an authorization restart close the
session before projection disclosure or a durable call-open rather than discovering the restart after the call
begins. The orchestrator then creates an at-least-128-bit random
preparation id and a distinct server-generated turn id, bound in process memory to the session id, role, world,
case, exact selection and model tuple, authorization boot id, issue time, and expiry. The response contains only
those public model/selection fields, the turn id, preparation id, issue time, and expiry. It contains no projection
item, authorization check id, system-use/policy binding, prompt, provider endpoint, credential, ruling, token, or
output.

The preparation lasts at most two minutes and no longer than its session. At most one is issued per session;
replacement, logout, expiry, selection change, authorization restart, or orchestrator restart burns it. A model
selection preparation from ADR-010 cannot be used as a model-turn preparation, and neither reference is accepted
on the other's route.

The strict use body is only `{preparation_id}`. The orchestrator atomically moves the matching preparation
`issued -> consuming` before any dependency or provider call. A replay, concurrent use, wrong session, or binding
mismatch makes no call. Immediately before invoking the coordinator it re-reads the current authorization-owned
selection and compares the complete stored binding; authorization's call-begin transaction remains the final
race boundary. The browser cannot supply a turn id, selection id, card/model identity, token limit, conversation
item, prompt, tag, clearance, actor, mandate, system-use fact, provider endpoint, or retry instruction.

The native orchestrator serializes ADR-010 selection use and M5.9 turn use under one case-local mutex. If a run
finishes first, a subsequent switch destroys every quarantined byte bound to the predecessor before returning the
selection response. If the switch finishes first, the turn's selection recheck/call-begin sees the new state and
the old preparation cannot disclose. Authorization's world mutex still closes races from another process request;
the local mutex supplies custody ordering, not authority.

### 2. The native process wires exactly the two reviewed acting lanes

Before its listener binds, the orchestrator process constructs both reviewed OpenAI-compatible adapters and one
`ModelTurnCoordinator`. The supervisor passes each lane's API key, endpoint override, and requested-model override
only to the orchestrator child. Authorization and services receive none of them. Both lanes must be present,
distinct, schema-valid, and mapped to the exact current signed card used by the mandate. The normalized base URL,
lane, requested id, and lane-specific token parameter must equal that card's signed `endpoint`,
`model.resolution.lane`, `model.requested_id`, and `capabilities.token_parameter` values. An environment override
may therefore reproduce the signed value but cannot silently redirect disclosure or relabel another endpoint;
changing one of these facts requires the existing card/mandate lifecycle first. Missing, ambiguous, stale, or
mismatched configuration prevents the orchestrator listener from binding. No secret value may enter stdout/stderr,
HTTP, errors, access/action records, fixture output, or test snapshots.

Configuration makes a provider callable; it never selects one. Only the current authorization transition chooses
the exact lane. There is no default derived from environment order, card order, adapter order, availability, or
fallback. A selected tuple absent from the configured map fails before disclosure. Provider timeout, refusal,
malformed output, served-model mismatch, authorization refusal, or a halted lane never invokes another lane.

`runtime:start` may initialize the adapters but makes no provider request by itself. Only successful consumption of
an exact browser preparation can call a provider in the native runtime. Unit and integration tests substitute
synthetic loopback provider listeners through an explicit dependency-injection/test-harness seam that is not
selectable by runtime environment, HTTP, or browser input and cannot be mistaken for signed provider evidence.
They must never contact an external endpoint. Live invocation and probing remain separate maintainer-approved
actions.

### 3. Authorization remains the only source of provider input and admission

The coordinator receives the server-held turn and selection binding. It first calls authorization's existing
`POST /model-calls/begin`. Only the returned, binding-checked projection becomes provider input. The preparation,
browser request, DOM, session storage, and orchestrator state cannot add, remove, reclassify, or retag an item.

The provider request retains the existing fixed system instruction, canonical projection envelope, no tools, no
caller-selected response format, and the existing vertical-slice ceiling of **512 output tokens**. That value is
code-fixed for M5.9 rather than browser- or environment-selectable. Authorization has already recorded the exact
call, selection, mandate/card/model, system-use, and projection digest before the adapter is invoked. A
selection or other governing fact that changes first makes call-begin fail; one that changes after disclosure is
contained by output admission and the existing eager invalidation paths.

Every provider response goes directly to authorization's existing output-admission route. Missing or malformed
served identity, tool calls, output-shape failure, provider substitution, stale selection, changed system-use or
other currentness failure, and lexical admission refusal retain the M5.3–M5.7 fail-closed behavior. The model output
has no code path to a ruling, commitment, effect, selection, or permission.

### 4. Browser status is metadata-only and disclosure-honest

The use response and same-session status read expose one bounded projection keyed by the server-generated turn id:

```text
{turn_id, selection_id, target, state, provider_disclosure,
 requested_id, served_id?, terminal_reason?, quarantine?}
```

`state` is one of `prepared | running | quarantined | withheld | discarded | failed`. `provider_disclosure` is
`none | possible | confirmed` and is derived from the coordinator branch, never asserted by the browser.
`served_id` appears only when confirmed response evidence exists. `terminal_reason` is a closed public class, not
raw provider, authorization, or network error text. A quarantined result may expose only the existing digest-bound
metadata and `release_state: sealed-no-release-path`; a withheld or failed result exposes no output metadata that
could be mistaken for retained content.

The orchestrator stores only the bounded run state needed for same-process status recovery. Selection change,
session close, or session expiry destroys affected quarantined bytes and changes any retained status to
`discarded` with a fixed reason; it never leaves `state: quarantined` after the bytes are gone. Process restart
destroys every session, preparation, status entry, and quarantined byte. Durable authorization records remain the
truth about open, terminal, and possible/confirmed disclosure; local recovery cannot upgrade, reconstruct, or
complete them. A lost or ambiguous browser response never causes an automatic retry. The browser may read the
known turn id while the same session and process remain active; after restart it must obtain a new handoff, and a
new provider call requires a new explicit preparation and gesture.

The coordinator's current lane-busy, replay, and fail-stop behavior remains in force. A terminal provider,
protocol, binding, admission, or quarantine failure halts that lane for the process lifetime; switching to another
approved lane is a separate ADR-010 gesture, and switching back does not silently clear the halt. No timeout,
reload, retry, or process recovery selects a fallback.

### 5. Output remains structurally unavailable

An admitted response is sealed in the existing module-private, bounded in-memory quarantine. M5.9 adds no read,
copy, rendering, release, proposal-construction, or conversation-store capability for those bytes. A withheld
response is discarded; a sealing/capacity failure destroys the bytes and fails the run. Browser responses,
console rendering, logs, access/action records, and status storage contain no prompt or model text.

`POST /w/{world_id}/cases/{case_id}/messages` remains `501`, `model_interaction_available` remains false, and the
case console must not show a chat composer. Its only new control says that it runs the selected model on the current
authorization-projected synthetic case state and that no response will be shown. User-entered text cannot reach a
provider in this slice. Output release, conversation ingestion of either user or model content, proposal creation
from output, semantic empathy checks, and M6 capture remain separately gated.

### 6. Access evidence and authority boundary

The authorization service continues to authenticate `proc:orchestrator` on call-begin, admission, and failure.
The orchestrator derives the case role/session provenance from its authenticated server-side session and attaches
it to all three calls as ADR-002 `claimed_actor` metadata; no browser header or body field supplies it. The claim
cannot satisfy a direct role-token route or become an input to mandate, system-use, selection, admission, ruling,
or commitment decisions.

The browser preparation and run are non-authorizing orchestration state. They create no mandate, system-use
decision, selection, ruling, reservation, nonce, commit token, commitment, effect, confirmation, permission, or
dialogue disposition. Provider disclosure is a recorded event, not action authority. The orchestrator still
reaches no authority-changing authorization endpoint, and an executing service still verifies a fresh single-use
commit token independently.

## Acceptance tests for the implementation tranche

- Startup fails before the orchestrator listener binds when either lane is absent, duplicated, malformed, stale, or
  does not exactly match its current signed card's normalized endpoint, lane, requested id, and token parameter.
  Child-environment tests prove lane secrets/configuration reach only the orchestrator and never output; starting
  the supervisor alone makes zero provider requests. The loopback test seam is dependency-injected and cannot be
  selected from runtime environment, HTTP, or browser input.
- All three browser routes require an exact active dynamic session and correct world/case. Both POSTs reject absent,
  foreign, and opaque Origin; the status read rejects a present foreign/opaque Origin. Static, role, process,
  handoff, expired, closed, and foreign-case credentials fail.
- Strict bodies reject message text and every caller-supplied turn/selection/model/mandate/system-use/projection,
  token-limit, tag, actor, provider, authority, retry, or extra field. `/messages` remains `501` and receives no
  downstream call. The native request uses the fixed 512-output-token ceiling.
- Preparation is current-selection-bound, session-bound, boot-bound, maximum two minutes, one per session, and
  domain-separated from ADR-010 preparation ids. Replacement, logout, expiry, selection change, either process
  restart, wrong session, replay, and concurrent use burn or refuse it without a provider call.
- The process-only current-selection envelope carries the authorization boot id. The browser mirror is constructed
  field-by-field in both the `selected` and `unselected` states—never by passing the dependency object through—and
  exact-key assertions prove both states omit the boot id. A boot mismatch closes the old session before call-open
  or projection disclosure. Authorization access evidence
  records the authenticated process separately from server-derived claimed session provenance on begin, admission,
  and failure, and ignores the claim for every decision.
- A use rechecks current selection, marks consuming before dependencies, and calls exactly the selected configured
  lane. A switch racing use yields only a mutex-consistent old-call or new-selection outcome; no stale projection,
  mixed binding, automatic retry, or fallback is possible.
- ADR-010 selection use and model-turn use share one case-local mutex. A successful switch destroys predecessor
  quarantine before returning, and selection change, session close, or expiry changes retained status to
  `discarded`; no status claims bytes remain after destruction. Authorization current-selection checks remain the
  safety boundary if local cleanup is interrupted or a direct process race bypasses the local ordering.
- Authorization durably opens the call before a synthetic loopback provider receives the exact digest-matching
  projection. Browser input cannot alter the provider request. Missing system-use/card/mandate/selection facts fail
  before disclosure.
- Synthetic loopback responses exercise matching served identity, substitution, missing/malformed identity, tool
  calls, oversized/malformed output, timeout, connection failure, admission refusal, post-response system-use or
  selection invalidation, quarantine capacity, and authorization-response binding corruption. Requested and served
  identities follow the existing durable evidence rules.
- Status is session-scoped, fixed, and content-free. Its disclosure state is branch-derived; ambiguous provider
  failure is never reported as `none`, and pre-provider refusal is never upgraded to `confirmed`. Lost browser
  responses can be read only while the same process/session survives and never trigger an automatic call.
- Admitted bytes remain module-private and digest-bound in quarantine; withheld/failed/capacity paths destroy them.
  No exported reader, browser response, log, record, proposal, conversation item, ruling, token, effect, or test
  snapshot contains prompt or output content.
- Existing M5.1–M5.8 behavior and tests remain green. Tests use only synthetic loopback providers and perform no
  live probe, external model call, key operation, card signing, generated-record edit, or M6 capture.

## Consequences and deferred work

M5.9 will complete the native selected-lane ingress portion of beat 19 and exercise beats 20–21 over real loopback
HTTP/process boundaries. It will not complete beat 19's user-visible model interaction, because admitted bytes remain
sealed and the browser cannot submit conversation content. Green tests will demonstrate the mechanism, not provider
quality, legal approval, independent assurance, or live endpoint behavior.

The next separately approved definition must decide the single-use release and authorization-owned conversation
ingestion contract before any model bytes or browser message can enter conversation state. Empathy-trigger
completion follows that content boundary. M6 remains blocked until the remaining M5 work is implemented and
reviewed.
