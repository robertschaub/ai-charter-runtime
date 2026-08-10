<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-013 — Governed proposal intake from admitted model output

**Status:** accepted and implemented in M5.11. The initial definition review at `a39dafd` returned NO-GO on two
documentation-contract findings, and the focused correction at `fbc72cc` received exact-SHA adversarial review GO
with no findings. The bounded implementation at `686cd9c`, plus its retry-idempotency regression at `8364745`,
received exact-SHA adversarial review GO with no remaining findings. The review's initial Low idempotency finding
was withdrawn after the locked transaction's existing exact-ruling dedupe and the regression were verified.
**Spec:** §3 (orchestrator proposes; authorization decides), §4 (structured proposal and gate-ruling contracts),
§5 (entry boundary, model selection, transactional core, and empathy layer), §6 criteria 1–5, §7 beats 3–6 and
19–21, and §10 M5.

## Context

M5.10 gives the dynamic case session an authorization-owned conversation: one case-officer message is durably
ingested as `said`, one admitted response may be consumed as `inferred`, and the browser renders only the exact-key
authorization transcript. It deliberately creates no proposal, ruling, commitment, or effect.

The M3 vertical-slice harness already asks a synthetic acting model for JSON, parses a small draft in the
orchestrator, fills a `FrozenProposal`, and submits it for a ruling. That is a deterministic test harness, not a
native case-session boundary: it uses fixed empty evidence arrays, has no binding to M5.10's durable conversation
version, and the headless execution route accepts a caller-carried frozen proposal. Exposing that shape to the
browser would let model-side code choose store items, tags, provenance, mandate/model bindings, or the gate being
run. It would also give admitted bytes a new consumer without the single-use, currentness, custody, and ambiguity
rules established by ADR-012.

Proposal construction must precede semantic dialogue-trigger completion. ADR-004/M5.1 accepts a dialogue response
only when its item reference is active in the case and canonically present in the frozen proposal. Without a native
proposal derived from current conversation state, beat 4 would remain a fixture-only exercise rather than the
declared user workflow.

M5.11 therefore adds one explicit proposal-preparation gesture, a purpose-bound model call, an authorization-owned
single-use proposal intake, and a fixed pre-commit gate sequence. It stops before Commit and effect execution. The
model supplies proposal semantics; it never supplies authority, classification, provenance, currentness, or gate
choice. The new references and lifecycle fields are protocol bookkeeping under spec §4, not new governance fields.

## Decision

### 1. Proposal preparation is a distinct dynamic-session gesture

The orchestrator origin adds these routes:

```text
POST /w/{world_id}/cases/{case_id}/proposal-preparations
POST /w/{world_id}/cases/{case_id}/proposals
GET  /w/{world_id}/cases/{case_id}/proposal-runs/{proposal_run_id}
```

Every route requires an exact active dynamic case-officer session bound to the path's world and case. The static
headless credential, role/process credentials, handoff values, expired/closed sessions, and foreign-case sessions
fail. Both POSTs require a present Origin exactly equal to the orchestrator origin; the GET rejects a present
foreign or opaque Origin. The routes use no cookies and emit no CORS headers.

Preparation has a strict empty body. Under the case-local mutex the orchestrator reads authorization's exact
current selection and conversation version. It refuses an unselected or empty conversation, an authorization boot
mismatch, an unconfigured lane, or malformed dependency evidence. It then creates an at-least-128-bit random
preparation id and a distinct proposal-run id bound in process memory to the session id, role, world, case,
authorization boot id, conversation version, exact selection/card/model tuple, issue time, and expiry.

The preparation lasts at most two minutes and no longer than the browser session. At most one proposal preparation
exists per session. Replacement, logout, expiry, conversation mutation, model switch, either process restarting,
or capacity refusal burns it. Its id is domain-separated from selection, projection-run, and message preparations.
The preparation response contains only the preparation id, proposal-run id, public selected-model tuple, issue
time, and expiry. It contains no conversation item, prompt, draft field, proposal id/hash, call/intake/release id,
authority binding, ruling, nonce, reservation, token, or model output.

Use has the strict body `{preparation_id}`. It moves the matching preparation `issued -> consuming` before any
dependency or provider call and rechecks the complete stored binding. The browser cannot supply proposal content,
item ids, case/turn/call ids, selection/model/card facts, mandate/system-use/policy facts, prompt, schema, output
limit, response format, service, action class, gate, retry instruction, or authority claim.

Proposal preparation/use shares the case-local mutex with message preparation/use, selection, projection runs,
release consumption, session close, and transcript reads. Authorization's world lock remains the safety boundary
for direct process races and durable transitions.

### 2. A proposal-purpose call is neither a chat call nor a projection-only run

Immediately before provider disclosure, the orchestrator asks authorization to begin one proposal-purpose call.
The strict process request adds a mutually exclusive proposal binding:

```text
{proposal_run_id, conversation_version, proposal_schema_digest}
```

It cannot coexist with ADR-012's message ingress binding. A call with neither binding remains ADR-011's
projection-only run. Authorization requires an exact active case-session provenance receipt, current boot,
selection, mandate/card/model tuple, policy, system-use decision, and conversation version. It recomputes the
acting projection under the world lock, requires at least one included item, records the ordered projection item
ids/digest and proposal binding in `model_call.open`, and returns only that projection as provider input.

The provider request uses one code-fixed system instruction, no tools, a fixed ceiling of 512 output tokens, and
the signed card's probe-tested native `response_format: json_schema` capability for the exact
`proposal-draft@1` schema. An absent or changed capability fails before disclosure. There is no prompted fallback,
automatic provider retry, alternate model, or caller-selected schema in this slice. A new provider call always
requires a new explicit browser preparation.

The existing served-model comparison and output-admission path remains mandatory. Withheld, tool-calling,
malformed, substituted, stale, expired, invalidated, or failed output creates no proposal intake. An admitted
proposal-purpose call receives one proposal-intake reference in its `model_call.complete` transaction and no
ADR-012 output release. A message-bound call may receive only a conversation release; a projection-only run
receives neither. One output can never be both conversation text and a proposal.

### 3. The model draft contains semantics and opaque evidence references only

The exact `proposal-draft@1` JSON object contains:

```text
{declared_objective, proposed_action,
 target: {recipient, resource},
 exact_parameters,
 material_input_ids, derived_claim_ids,
 data_to_be_disclosed,
 cost_obligation: {amount_minor_units, description},
 material_consequences, reversibility_class,
 commercial_influence: {applicable, note}}
```

It is a strict object with bounded strings/arrays, integer-only amounts, the existing canonical
`exact_parameters` value regime, no duplicate JSON object keys, and at most 32,768 UTF-8 bytes. The two id arrays
contain unique ids and are disjoint. They are references, not caller-supplied store objects.

The draft has no world/case/proposal/action/revision/time fields, selection or model evidence, mandate reference,
service/action class, item text/store/tags/provenance, policy/system-use fact, proposal hash, gate, ruling, nonce,
reservation, token, or disposition. Unknown, missing, duplicate, ill-typed, non-canonical, non-Unicode, or
out-of-bound content is refused. JSON parsing must reject duplicate keys rather than silently accepting the last
one.

Authorization resolves every `material_input_id` to one exact active `said` or `confirmed` item and every
`derived_claim_id` to one exact active `inferred` item. `permitted` items are not factual proposal basis and are
refused in either list. Every item must belong to the configured case, have been included whole in the exact
recorded provider projection, and remain canonically identical at intake. Cross-case, removed, replaced,
projection-dropped, misclassified, duplicated, or caller-reconstructed items fail closed.

Authorization then constructs `FrozenProposal` field-by-field. It copies the model-supplied semantic fields,
copies the resolved whole store items into `material_inputs` and `derived_claims`, and supplies the world,
at-least-128-bit proposal/action ids, revision `1`, authorization timestamp, current selection, confirmed
requested/served/card evidence, current mandate reference, and ADR-007 proposal hash. The current mandate supplies
the connected service and action class used by the later gate sequence; neither is inferred from free text or
accepted from the caller.

Shape, provenance, binding, and currentness validation do not prove that the model's proposal is complete,
truthful, lawful, fair, or wise. The fields remain a model proposal that the independent gate must decide.

### 4. Proposal intake is durable, single-use, and content-bound

The admitted call transaction issues one process-only record:

```text
{proposal_intake_id, proposal_run_id, authorization_boot_id,
 call_id, case_id, session_id, conversation_version,
 selection_id, mandate_id, mandate_version,
 card_id, card_version, requested_id, served_id,
 system_use_decision, policy_version, policy_content_digest,
 projection_digest, projection_item_ids,
 output_digest, proposal_schema_digest,
 issued_at, expires_at, state, proposal_id?, refusal_reason?}
```

The intake id is at least 128 random bits, lasts at most two minutes, and has state
`issued | consumed | refused | invalidated | expired`. Refusal reasons are a fixed public-safe vocabulary and
carry no raw JSON, parse error, prompt, model text, endpoint, or credential. The proposal-run id is the only
browser-known correlation id; the intake id and full binding remain process-only.

The authorization service adds:

```text
POST /w/{world_id}/proposal-intakes/{proposal_intake_id}/consume
GET  /w/{world_id}/proposal-intakes/{proposal_intake_id}
GET  /w/{world_id}/cases/{case_id}/proposal-runs/{proposal_run_id}
```

All three accept only `proc:orchestrator`, are `authorityChanging: false`, Origin-guarded and access-recorded, and
have strict fixed projections. Freezing model-proposed evidence creates no action authority.
The intake-id GET is the ambiguity-recovery read; the case/run-id GET lets an orchestrator recover durable status
without retaining or revealing the intake id. Consume accepts only `{content}` from the module-private quarantine
consumer. Under the world lock authorization requires an exact issued, unexpired, same-boot intake and admitted
call; rechecks the case session receipt, conversation version, selection, mandate/card/model, policy, system-use
decision, projection, schema, and output digest; parses and resolves the draft as §3 requires; and atomically
appends the frozen proposal, its proposal-origin sidecar, and the intake transition to `consumed`. The sidecar binds
the proposal hash to the exact case, conversation version, call, session provenance, projection items/digest,
output digest, selection, model evidence, and system-use/policy facts without changing the spec's proposal schema.

Invalid content or evidence references atomically changes the intake to `refused` with no proposal. Changed
authority or conversation invalidates/refuses it with no partial write. An exact replay of a consumed intake with
the same content returns the recorded content-free result; changed-content reuse or any other state fails closed.
Both GETs are metadata-only and can neither consume, revive, nor return content. The case/run-id read refuses a
wrong case and returns no intake id.

The quarantine adds a proposal consumer as a module-private capability distinct from the conversation-release
consumer. It removes local custody before sending one copy, and zeroes the buffer on success, fixed refusal, or
ambiguous transport outcome. After ambiguity the coordinator may perform only the intake-status GET. Confirmed
consumption continues from the durable proposal; otherwise the output remains unavailable. Content is never
automatically retransmitted and the provider is never automatically called again.

### 5. Authorization owns the fixed Authorize → Submit → Verify sequence

After confirmed proposal freeze, the orchestrator may invoke:

```text
POST /w/{world_id}/proposals/{proposal_id}/precommit
GET  /w/{world_id}/proposals/{proposal_id}/precommit
```

Only `proc:orchestrator` is accepted. The POST is conservatively `authorityChanging: true`, matching the existing
`proposal.submit` classification because it can issue rulings and open an escalation; the read-only GET is
`authorityChanging: false`. Both routes are Origin-guarded and access-recorded. The POST has a strict empty body:
the caller cannot carry a proposal, select a gate, provide context/signals, skip a stage, name a service/action
class, or request Commit. Authorization loads the exact stored proposal and origin sidecar and runs the existing
gates in the fixed order Authorize, Submit, Verify. It stops at the first deny or escalate. It runs a later gate
only after the previous allow is durably confirmed, and each gate remains idempotent for the exact proposal hash
and gate.

Before each gate authorization rechecks that the proposal-origin conversation version is current and every basis
item remains active and exact. The existing gate path independently rechecks selection, mandate/card/model,
policy, system-use decision, screening evidence, and authority defects. An ambiguous response is resolved through
the read-only precommit status; without durable proof of the prior allow, no later gate runs. No model call,
proposal-content retransmission, or alternate lane is used to recover a gate response.

The classification tracks durable ruling/escalation mutation; it does not let the orchestrator decide the result
or change standing authority. The precommit operation can issue only
Authorize/Submit/Verify rulings and their records; it cannot issue a Commit ruling, reserve a counter, consume a
nonce at commitment, mint a commit token, call a service, or create an effect. Dynamic browser sessions remain
unable to use the static headless `/actions/execute` seam. The legacy full-proposal submission route remains a
headless deterministic-test interface and is not widened or accepted from a dynamic session.

M5.11 does not change screening-signal or dialogue-routing semantics. A current policy deny or escalation is
recorded and stops the sequence. ADR-004's focused question, standing validation, response, and proposal-revision
continuation are completed separately in M5.12. ADR-014 is the reviewed definition for that bridge; it reuses this
ADR's proposal call, intake, freeze, and precommit boundaries without widening the M5.11 implementation.

### 6. The browser sees a redacted proposal and gate evidence, never raw model JSON

The proposal-run status is constructed from authorization-owned durable state and contains exact keys for:

```text
{proposal_run_id,
 state: prepared | running | frozen | denied | escalated | verified | failed,
 proposal?, gates, escalation_id?}
```

The optional proposal projection contains proposal/action ids, revision, declared objective, proposed action,
target, exact parameters, data to be disclosed, cost/obligation, material consequences, reversibility class,
commercial-influence statement, requested/served model ids, and a field-by-field basis view containing only
`said | confirmed | inferred-unconfirmed` plus text. Each gate projection contains gate, ruling id, verdict, UX
class, reason, status, and validity window. The console labels these as model-proposed and pre-commit gate evidence,
not an approval, instruction to file, legal/factual clearance, commitment, effect, assurance, or certification.

The browser schema omits raw provider JSON, prompt/system instruction, proposal-intake/call/output or projection
digests, intake/release ids, store item ids, tags/provenance, session/boot/selection ids, card digest/key,
mandate/system-use/policy internals, screening rationale, nonce, reservation, commit token, credential, endpoint,
and provider error. Process-only status may carry the bounded ids/digests needed to verify transport recovery but
never content. Both browser basis variants are constructed field-by-field and exact-key tested. Bounds are checked
before response; history is never silently truncated or widened.

A lost browser response can be recovered by proposal-run id while a valid session for the same case exists. A new
valid handoff may read a durably frozen proposal after orchestrator restart. It cannot recover unconsumed bytes,
invent a proposal, or continue a gate absent durable authorization evidence.

### 7. Invalidation, replay, and authority boundary

Conversation mutation, selection change, mandate/card/policy/system-use change, or authorization restart eagerly
invalidates affected issued proposal intakes and issued rulings where the existing lifecycle supplies an
invalidation path. Intake consume and every precommit gate perform the lazy currentness check. A frozen proposal
remains immutable historical evidence; changed conversation requires a new proposal/revision and cannot silently
retag or refresh it.

An orchestrator restart destroys local preparations and quarantined bytes. Authorization replay restores intake,
proposal-origin, proposal, gate, and refusal state deterministically. Recovery cannot turn `issued` into
`consumed`, manufacture model text, fill missing proposal fields, advance a gate, or upgrade a deny/escalate.

Proposal intake and precommit evaluation create no mandate, system-use decision, model selection, confirmation,
permission, Commit ruling, counter reservation, commitment, token, service call, effect, or M6 artifact. Model
output never authorizes. The authorization service decides each gate under current authority, and every future
consequential effect still requires a separate executing service to verify a fresh single-use commit token.

## Acceptance tests for the implementation tranche

- All browser routes require the exact active dynamic case session and correct world/case. POSTs reject absent,
  foreign, and opaque Origin; the GET rejects a present foreign/opaque Origin. Static, role, process, handoff,
  expired, closed, prior-boot, and foreign-case credentials fail.
- Preparation has an empty strict body, uses a non-empty current conversation, binds session/boot/version/selection
  and exact lane, lasts at most two minutes, is one-per-session, and is domain-separated. Replacement, message
  mutation, switch, logout, expiry, restart, replay, concurrent use, and capacity refusal burn it without a call.
- The browser cannot supply proposal fields, evidence ids, schema/prompt, model/authority facts, service/action
  class, gate, retry, or output limit. The provider request is fixed to the current authorization projection, no
  tools, 512 output tokens, and the exact signed-card-supported `proposal-draft@1` JSON schema.
- Proposal-purpose, message-bound, and projection-only calls are mutually exclusive. Only one admitted
  proposal-purpose call receives one proposal intake; it receives no conversation release and its bytes never
  become a conversation item.
- Missing structured-output capability, empty/dropped projection, stale conversation, absent system-use/card/
  mandate/selection, provider failure, tool call, served-model mismatch, lexical withholding, malformed JSON,
  duplicate keys, extra fields, oversized output, or schema mismatch creates no proposal.
- Authorization resolves draft ids only to exact active whole items in the recorded projection: `said|confirmed`
  for material inputs and `inferred` for derived claims. Cross-case, removed, replaced, dropped, `permitted`,
  duplicate, intersecting, reconstructed, or misclassified references fail with no partial write.
- The frozen proposal is constructed field-by-field with authorization-generated ids/time/revision/hash and exact
  call-derived selection/model/mandate evidence. Caller attempts to inject tags, provenance, store items, hash,
  service/action class, currentness, or authority are structurally impossible.
- Intake issue, consume/refuse/invalidate/expire, proposal freeze, and proposal-origin sidecar replay exactly.
  Exact consumed replay creates no second proposal; changed-content replay fails. Corruption, missing pairings, or
  impossible transitions fail startup rather than being reconstructed.
- Proposal quarantine transfer removes and zeroes bytes on every outcome. A lost consume response causes no
  content retransmission or provider retry; status may prove an existing proposal but cannot create or revive one.
- Precommit accepts no caller-selected gate and runs only Authorize → Submit → Verify over the stored proposal,
  stopping on deny/escalate/ambiguity. Conversation or authority change between gates prevents the next gate.
- Precommit creates no Commit ruling, reservation, commit token, service call, effect, or executable browser
  capability. Dynamic sessions and their bearers are rejected on the headless action-execution route.
- Browser and process proposal projections are exact-key and field-by-field. They expose the bounded proposal and
  gate evidence but omit raw JSON, internal ids/digests/bindings, tags/provenance, credentials, errors, tokens, and
  every authority-bearing secret. Labels never present an allow as a green light or assurance.
- Switch/proposal, message/proposal, release/proposal, dialogue/proposal, session-close/proposal, and restart races
  yield only lock-ordered declared outcomes. Frozen history is never silently refreshed after a case change.
- Existing M5.1–M5.10 behavior and tests remain green. Tests use deterministic ids/clocks, synthetic fixtures, and
  loopback providers only; no live probe/provider call, key operation, card signing, generated/append-only record
  edit, push, empathy completion, action effect, or M6 capture occurs.

## Consequences and deferred work

The reviewed M5.11 implementation replaces the synthetic caller-carried proposal gap with a native,
conversation-bound, model-proposed,
authorization-frozen artifact and fixed pre-commit evidence sequence. It does not make a proposal true, safe,
lawful, approved, committed, or executed, and it does not complete M5.

The M5.12 candidate implements ADR-014's semantic `unconfirmed_inference_as_fact` dialogue-trigger routing and
response-driven proposal revision. Commit/effect initiation from the dynamic case session, broader ingestion
roles, retention and deletion propagation, live provider runs, and M6 capture remain deferred. The two non-blocking
M5.10 transaction-shape hardening observations remain separately deferred rather than being hidden inside this
slice.
