<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-014 — Native dialogue trigger and proposal-revision continuation

**Status:** proposed M5.12 definition only; not reviewed and not approved for implementation.
**Spec:** §4 (proposal revisions, screening signals, intervention contract), §5 (empathy layer and disposition
continuation), §6 criteria 1, 2, 4, and 5, §7 beat 4, and §10 M5.
**Depends on:** ADR-004, ADR-005, ADR-009, ADR-012, and ADR-013.

## Context

M5.1 already makes an authenticated ADR-004 dialogue response an authorization-owned, atomic conversation
transition. M5.11 now freezes a native model-proposed artifact and runs the fixed Authorize → Submit → Verify
pre-commit sequence. The missing bridge is narrower than either mechanism: a Verify-stage
`unconfirmed_inference_as_fact` signal must become one focused, correctly routed dialogue escalation, and an accepted
state-changing response must make one explicit, native proposal revision possible without letting the model,
browser, or orchestrator manufacture standing, authority, lineage, or a successor ruling.

The existing headless `/escalations/{id}/revision` route accepts a complete caller-carried proposal after the general
`narrow-or-modify` disposition. It remains a deterministic M4 test seam. Widening it to the dynamic browser would
undo M5.11's native proposal boundary. M5.12 therefore adds a distinct authorization-owned preparation binding and
reuses M5.11's schema-bound provider call, quarantine, intake, freeze, and precommit machinery.

This ADR adds protocol bookkeeping only. It changes no Charter governance-semantic field and does not move the
upstream provenance pin.

## Decision

### 1. Authorization derives the dialogue trigger from exact current evidence

The bounded M5.12 trigger is the Verify-stage screening signal `unconfirmed_inference_as_fact`. It is eligible for a
dialogue escalation only when authorization can resolve exactly one distinct `suspect_item_id` across the relevant
signals to an item that is all of the following:

- active in the authorization-owned case conversation;
- `store: inferred`;
- canonically identical to a `derived_claims` item in the exact frozen proposal being verified;
- present in the exact proposal-origin projection; and
- bound to the same case, conversation version, selection, model/card, mandate, policy, and system-use decision as
  that proposal.

The screening model supplies a signal and suspect reference as evidence only. Its rationale, suggested question,
standing, route, confidence wording, and disposition have no authority. Authorization independently validates the
suspect binding and derives the question and intervention contract. Zero, multiple, foreign-case, removed,
reconstructed, material-input, misclassified, or proposal-absent suspects cannot open a dialogue escalation. The
signal still cannot allow: authorization returns a general fail-closed Stop under the policy's non-dialogue review
contract when it cannot safely form the bounded question.

For beat 4, authorization constructs the focused question from the code-fixed template
`What cited evidence confirms, corrects, or narrows this inference: "{exact inference text}"?`; it never uses
model-supplied question prose. All six intervention-contract fields are fixed to:

```yaml
trigger_and_state: { trigger: unconfirmed-inference-as-fact, state: open }
decision_and_route:
  eligible_role: case_officer
  standing_class: third-party-fact
  competence_declared: Assigned case officer for the synthetic demo (declared, not verified).
  independence_declared: Not independently verified in this POC.
  substitute_roles: [principal]
  substitute_rule: The principal may respond only under the same standing and cannot manufacture a third-party fact.
decision_basis_shown: [frozen-proposal-inference, current-evidence-status]
response_bound_and_default:
  response_bound_ms: 900000
  safe_default:
    kind: stop-remains
    disposition: abstain
    authority_basis: { kind: no-new-authority }
    reversible: true
permitted_dispositions: [confirm, correct, narrow, abstain, route]
record_and_feedback:
  record_events: [dialogue_trigger_raised, dialogue_response_recorded]
  feedback_consequence: Increment the dialogue ask-rate counter.
```

`permit` is deliberately absent: permission to retain information cannot confirm an inferred third-party fact.
`confirm` continues to require resolvable cited evidence or routing to the applicant; a case officer's bare assertion
cannot manufacture the factual basis. The existing general Submit signal rule no longer captures this signal before
Verify. A specific Verify policy rule and a general fail-closed Verify fallback preserve the signal-never-allows
invariant.

The exact inference is bounded by the existing conversation/proposal schemas and is interpolated only as data. The
authorization-origin console renders the generated question as text, never as HTML or executable markup.

An escalation created by this path carries a protocol-only `dialogue_item_ref` bound to the exact inference. It is
required on new dialogue escalations and null on general escalations. Replay validates the reference against the
source proposal, case, and trigger record. Historical records remain readable but cannot acquire a binding by
reconstruction.

### 2. The existing direct response boundary remains authoritative

The responder still reads and answers only on the authorization origin through ADR-004's role-token route. The
orchestrator and dynamic case session never receive the question, contract, answer, evidence payload, role token, or
conversation-store mutation.

For `confirm`, `correct`, or `narrow`, `scope.item_ref` must equal the escalation's exact `dialogue_item_ref`, not
merely any item in the proposal. Authorization rechecks inside the response transaction that the item is active,
case-local, inferred, and canonically present in the frozen source proposal. The existing bare-confirm, role,
evidence, disposition, timeout, and single-use checks remain unchanged.

The accepted response, source-ruling invalidation, escalation disposition, conversation invalidations, store
remove/put operations, conversation-version advance, and response record append remain one WAL transaction. The
response record carries the answer digest, exact scope, responder role, and resolved evidence; raw answer text is
durable only in the authorization-owned `said` entry. No response issues a ruling, grants authority, starts a model,
or silently continues the action.

`confirm`, `correct`, and `narrow` may make a proposal revision available. `abstain` leaves the Stop in place and
`route` parks the case; neither enables revision in this slice. The broader ADR-004 `permit` transition remains
implemented for an eligible permission dialogue, but it is not emitted by this beat-4 trigger and is outside the
M5.12 native-continuation path.

### 3. Revision preparation is explicit, authorization-owned, and single-use

After an eligible response is durably disposed, the case console may make one explicit empty-body request:

```text
POST /w/{world_id}/cases/{case_id}/proposal-runs/{source_proposal_run_id}/revision-preparations
```

This is an orchestrator-origin browser route. It requires the exact active dynamic case-officer session, the exact
case, and a present exact Origin. The source run id selects only a visible historical run; it carries no response,
proposal, authority, model, gate, or successor facts. Authorization, not the browser or orchestrator, decides whether
that run currently has an eligible continuation.

The orchestrator calls the same path on the authorization origin under `proc:orchestrator`, with the case-session
claim as provenance. The body is strictly empty. The process route is `authorityChanging: false` because it creates
only a short-lived protocol credential and cannot change a mandate, ruling, escalation, commitment, or effect. It is
nevertheless Origin-guarded and access-recorded. An exact retry for the same session, source run, and unchanged
current state returns the same issued preparation; ambiguity cannot create parallel continuation authority.

Authorization durably issues one maximum-two-minute `proposal_revision_preparation` containing protocol bindings to:

- authorization boot and exact case-session receipt;
- source proposal run, proposal id/hash, action id, and revision;
- source ruling and dialogue escalation;
- exact `dialogue_item_ref`, terminal disposition, and dialogue-response record entry;
- post-response conversation version and exact current projection digest;
- current selection, requested model, signed card evidence, mandate, policy, and system-use decision;
- code-fixed revision prompt/schema digest; and
- authorization-generated next proposal-run id and expected next action revision.

Its record lifecycle is `issued → consumed | expired | invalidated`. Across all sessions, at most one preparation may
be issued, or consumed into a nonterminal call/run, for the exact source response/action/currentness tuple. An exact
same-session retry returns the issued preparation; another session or concurrent request conflicts while that live
preparation or run exists. It is consumed atomically with model-call begin, before provider contact, and its
`expires_at` remains the hard deadline for every pre-freeze admission and intake step after consumption.

Session close/expiry, response replay, conversation mutation, model switch, mandate, card, policy, or system-use
change, a claimed successor, a newer action revision, or TTL expiry transitions an issued preparation to
`invalidated` or `expired`. After consumption the same drift makes the binding noncurrent: every later admission,
intake, freeze, and gate boundary refuses it, and a late provider result cannot be admitted. Authorization restart
invalidates issued records and makes prior-boot consumed bindings noncurrent. Orchestrator restart destroys the only
local wrapper and quarantined bytes; an unreachable issued record or consumed pre-freeze run stops blocking no later
than its fixed expiry. Invalidation never calls a provider and never manufactures a replacement. After a terminal
pre-freeze call/run failure or an invalidated/expired preparation, a valid session may explicitly request a fresh
preparation under current state.

### 4. The revision call reuses M5.11 containment with a domain-separated prompt

The browser uses the existing proposal-use route with only the opaque preparation id:

```text
POST /w/{world_id}/cases/{case_id}/proposals
{ "preparation_id": "…" }
```

The orchestrator consumes its local wrapper before dependencies and passes only the authorization-owned revision
preparation reference to model-call begin. Initial proposal, revision proposal, message-bound, and projection-only
purposes remain mutually exclusive. The model-call record binds the source proposal/action/revision, response record,
post-response conversation version, projection digest, and expected next revision through the consumed preparation.

The provider request is fixed to `proposal-revision@1`: no tools, 512 output tokens, the same exact
`proposal-draft@1` native JSON schema, and a code-fixed revision system instruction. Its input is constructed
field-by-field from:

- the refreshed authorization projection after the dialogue response; and
- a semantic-only projection of the source proposal.

The source projection may contain the semantic proposal fields already permitted in the M5.11 browser proposal view.
It contains no proposal, action, ruling, escalation, response-record, or transport ids; authorization binds those
out of band. It also omits store ids/tags/provenance, authority bindings, screening rationale,
contract/answer/evidence records, credentials, digests, and transport state. The refreshed conversation projection
retains only the exact current item references required by the proposal schema. Response text reaches the model only
if it is an active `said` item allowed by that current provider projection; neither the dialogue record nor this
protocol creates a disclosure bypass.

Admission, quarantine transfer, duplicate-key and schema parsing, exact-item resolution, intake single use, and
ambiguity recovery remain ADR-013's mechanisms. The model again supplies only proposal semantics and current item
references. Authorization constructs the frozen revision field-by-field with:

- a new proposal id and hash;
- the source proposal's exact `action_id`;
- `revision = latest durable revision for that action + 1`;
- current selection/model/card/mandate/policy/system-use evidence;
- current active material and derived items; and
- a proposal-origin continuation sidecar binding the source proposal, escalation, response record, and consumed
  revision preparation.

The caller cannot choose the action id, revision, source proposal, dialogue item, response basis, or successor.
Consumed replay returns the same frozen revision; changed bytes or changed lineage conflict. Every frozen proposal,
including one later denied, remains immutable, so a later attempt uses `latest frozen durable revision + 1`. A
terminal provider or intake failure before freeze leaves immutable run/call evidence but creates no proposal
revision; a fresh preparation therefore targets the same next revision number under new preparation, run, and call
ids rather than inventing a gap or overwriting evidence.

### 5. Fixed precommit rechecks currentness and claims the successor atomically

The revised proposal uses ADR-013's existing strict empty-body precommit route and fixed
Authorize → Submit → Verify order. Before every gate, authorization additionally verifies the consumed revision
preparation, source proposal/action lineage, disposed eligible dialogue response, exact response record,
`dialogue_item_ref`, post-response conversation state, and absence of an already claimed successor.

Authorize and Submit allows do not claim continuation. The transaction that issues either the first escalate ruling
or the final Verify allow atomically links both the source ruling and source escalation to that exact successor. A
deny is recorded but does not claim the link. A later attempt must be a newly frozen next revision and rerun all three
gates. Concurrent precommit attempts serialize: at most one escalate or final Verify allow can claim the successor;
losers fail as already continued without issuing further authority evidence.

The human response is basis evidence only. It never converts the invalidated source ruling to allow and never skips
a gate. The successor remains pre-commit evidence: M5.12 cannot issue Commit, reserve a counter, mint or expose a
token, call an executing service, or create an effect.

### 6. Browser status is redacted and recovery is read-only

The existing proposal-run status adds a field-by-field revision-continuation projection. For the source run it may
show only `unavailable | response-required | available | prepared | continued | parked`; for a revision run it may
show only the source run id and current proposal/gate state. The browser may receive its local preparation id,
expiry, and authorization-generated new proposal-run id only as required for the existing two-step flow.

It never receives `dialogue_item_ref`, response record id, answer/evidence content or digest, source proposal hash,
action lineage internals, preparation/model-call/intake ids, projection/prompt/schema digests, boot/session receipt,
selection/card/mandate/policy/system-use bindings, screening rationale, nonce, reservation, token, or credential.
Every browser/process schema is strict, bounded, field-by-field, and exact-key tested.

A lost response is recovered only by the existing read-only proposal-run status and durable authorization state.
Recovery never retransmits content, repeats a provider call, reopens a dialogue response, revives an expired
preparation, or infers a successor from browser state. A new valid same-case handoff may view durable status but must
make a fresh explicit preparation under current state before any unstarted revision call.

### 7. The `reverse` finding and later milestones remain separate

M5.12 uses only ADR-004's `DIALOGUE_DISPOSITIONS`. It neither enables nor interprets the separate general
`reverse` token recorded as an open finding in the implementation plan. No M5.12 policy rule may list a general
disposition, and no general escalation may enter the native dialogue-continuation path.

Dynamic-session Commit/effect initiation, service execution, wider dialogue classes, broader conversation ingestion,
retention/deletion propagation, live provider runs, M6 capture, and the `reverse` disposition decision remain
separate and unapproved. M5.12 does not complete M5.

## Acceptance tests for a later implementation tranche

- A Verify-stage `unconfirmed_inference_as_fact` signal opens a dialogue escalation only for exactly one active,
  case-local, exact inferred item in the frozen proposal and recorded projection. Missing, multiple, material,
  removed, reconstructed, cross-case, or caller-selected suspects produce a fail-closed non-dialogue Stop and no
  question.
- The focused question and all six schema-shaped contract fields are authorization-derived exactly as §1 fixes
  them. The console renders the bounded inference as text, the contract is routed to the case officer, has
  `third-party-fact` standing, permits only `confirm|correct|narrow|abstain|route`, and defaults to `abstain`.
  Signal rationale, inference markup, and caller context cannot alter the template or contract.
- The authorization-origin role route preserves wrong-role, bare-confirm, cited-evidence, disposition, strict-body,
  timeout, late-response, and single-use behavior. `scope.item_ref` must equal the bound `dialogue_item_ref`.
- Response disposition, ruling invalidation, conversation changes/version advance, record append, and preparation
  invalidations are one replayable transaction. Raw answer and evidence content remain absent from orchestrator,
  browser, access, action, and process output.
- The new browser and authorization revision-preparation routes have strict empty bodies, exact session/case/Origin
  and `proc:orchestrator` ACLs, bounded access evidence, idempotent ambiguity handling, maximum-two-minute single
  use, and exact route classifications.
- Preparation is unavailable before an eligible response and after `abstain`, `route`, timeout, successor claim,
  session/boot change, conversation mutation, model switch, authority/currentness change, expiry, or replay. Exactly
  one live preparation/pre-freeze run exists across sessions; concurrent, replacement-session, restart, and late
  provider-completion cases serialize or fail before admission.
- Revision use consumes before provider contact and cannot accept prompt, proposal, response, model, lineage,
  authority, gate, retry, or output-limit facts from the browser/orchestrator. No automatic retry or fallback occurs.
- The provider receives only the fixed revision instruction, same strict proposal JSON schema, current permitted
  projection, and redacted semantic source proposal. It receives no dialogue record, authority binding, credential,
  or hidden transport metadata.
- Authorization freezes a new proposal id/hash with the same action id and exact next frozen durable revision; item
  references resolve only from the refreshed active projection. A frozen denial advances the next revision; a
  terminal pre-freeze failure leaves immutable run/call evidence but does not consume a revision number. Replay
  preserves the continuation sidecar and fails startup on orphaned, reconstructed, noncontiguous, or contradictory
  lineage.
- Precommit remains fixed Authorize → Submit → Verify. Only an escalate or final Verify allow atomically claims the
  source successor; deny does not. Concurrency, ambiguity, restart, and repeated calls cannot create two successors
  or duplicate exact-gate rulings.
- Real-listener and native three-process tests exercise beat 4 with synthetic loopback providers and registry
  evidence: trigger → bare-confirm refusal → cited confirmation → refreshed projection → revision freeze → gates
  rerun. The path stops before Commit and proves zero reservations, commitments, service calls, and effects.
- Exact-key tests prove the browser never receives question/contract/answer/evidence, dialogue item ref, source hash,
  internal lineage/currentness bindings, raw provider bytes, credentials, or action authority. UI text labels the
  proposal as model-proposed and the dialogue response as evidence, never approval or factual certification.
- Existing M4 and M5.1–M5.11 behavior remains green. Tests use deterministic clocks/ids, synthetic fixtures, and
  loopback providers only. No live probe/provider call, key operation, card signing, generated/append-only record
  edit, push, Commit/effect path, `reverse` behavior, or M6 capture occurs.

## Consequences

This definition would complete the native beat-4 bridge from an exact unconfirmed inference through a direct
authorization-owned response to a fresh, fully re-gated proposal revision. It preserves the boundary that the model
proposes, authorization decides, and no effect exists without a later executing-service commitment check.

It deliberately adds another explicit user gesture after response and another short-lived protocol credential. That
cost makes response authority, provider disclosure, and proposal continuation separately observable and prevents an
answer from becoming an automatic instruction to act.
