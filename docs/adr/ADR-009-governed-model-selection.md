<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-009 — Governed model selection and switching

**Status:** accepted; implementation reviewed at `442397a` with GO — no findings (2026-08-05).
**Spec:** §3 (case-console model picker),
§4 (mandate, ruling, and model-card bindings), §5 (model navigation and selection), §7 beats 14 and 19–21,
and §10 M5.

**Implemented and reviewed (M5.8 browser initiation, definition `85fef1f`, implementation `ff9e438`,
2026-08-06):**
ADR-010 binds the existing process protocol to
an exact dynamic case session, a refreshed two-minute browser preparation, and a separate user selection gesture.
Authorization check ids remain hidden, and the browser cannot supply the predecessor used for selection;
case-session provenance is recorded only as a caller claim and never participates in authority.

## Context

The specification makes selection within the mandate's approved acting-model set a case-level act. It must
follow **find → check → use**, re-project for the selected provider, re-arm Submit and Verify, record the
transition, and invalidate prior in-flight authority. It must never turn card evidence, a model result, or an
orchestrator assertion into action authority.

At reviewed baseline `6884e8c`, the repository had an M3-era `model.select` WAL shape and
`recordModelSelection(proposal)` helper.
They record a completed proposal after provider service and therefore cannot govern which model may receive
the next projection. The helper accepts proposal-carried served-model evidence, has no current case selection
or predecessor check, and is absent from the authenticated process boundary. M5.7 replaces that legacy
meaning; it does not expose it as a shortcut.

M5.7 is deliberately headless. It freezes and implements authorization-owned selection state and its
authenticated process protocol before any browser message route, native provider loop, conversation ingestion,
or output-release consumer is opened.

## Decision

### 1. The mandate names the default; authorization owns current selection

The mandate gains one HMAC-bound `default_acting_model` reference:

```json
{
  "card_id": "publicai-apertus-v1.5-70b",
  "card_version": 1,
  "requested_id": "swiss-ai/apertus-v1.5-70b"
}
```

It must match exactly one `approved_models` entry carrying the `acting` role. Array order is never a default.
An initial selection may name only this reference. A later switch may name any other exact, current acting entry
in the same mandate. Changing the approved set or the default remains a principal-only mandate amendment;
selecting within that set neither widens the mandate nor changes action authority.

The authorization service materializes one current selection per configured case from append-only transitions.
No software default, environment variable, card ordering, caller-supplied clearance, or provider response may
choose it. The bounded POC still has one configured case and requires exactly one active mandate; expanding to
multiple cases requires an explicit case-to-mandate relation rather than reusing that shortcut.

### 2. Find → check → use is a two-step, single-use protocol

The existing approved-model projection remains the plural **find** view. M5.7 adds an orchestrator-only
headless **check** operation for one target and a separate **select** operation:

```text
GET  /w/{world_id}/cases/{case_id}/model-selection
POST /w/{world_id}/cases/{case_id}/model-selection-checks
POST /w/{world_id}/cases/{case_id}/model-selections
```

The fixed read returns the current transition and its latest confirmed observation, or an explicit unselected
state. ADR-011's proposed M5.9 amendment also adds the current authorization boot id to this process-only envelope
so a stale case session can be closed before call-open; the browser mirror redacts it. The read is the recovery path
after either process restarts; clients never infer current selection from card order, environment, or their own
cache. It is orchestrator-only, non-authorizing, Origin-guarded, and access-recorded.

The strict check request carries only:

```text
{expected_current_selection_id: id | null,
 target: {card_id, card_version, requested_id}}
```

Authorization injects the configured case, resolves the sole active mandate, verifies the exact signed card and
key, computes the current acting-role disclosure intersection, resolves the exact system-use decision, and returns
the fixed card-evidence projection plus a check reference. The boot-bound reference contains a random id,
world/case, authenticated process actor, expected predecessor, mandate/version, exact target, card digest and
verifying key id, system-use reference, issue time, and a maximum five-minute expiry. It contains no credential,
model text, prompt, ruling, nonce, reservation, or token.

Five minutes is the headless protocol's safety ceiling, not a claim about adequate human review time. The later
browser slice must define and review its own gesture/session timing and evidence-refresh protocol rather than
silently inheriting this placeholder.

Check issue is appended and fsynced before the reference leaves authorization. Its replayed lifecycle is
`issued → consumed | expired`; the sweeper may append expiry, but every consume checks time lazily. A restart makes
every prior-boot issued check unusable even before the expiry marker is appended. The check id is correlation
metadata, not a bearer credential: only the authenticated orchestrator route can consume it, and every binding is
rechecked. A target whose card is missing, invalid, withdrawn, superseded, or marked
`re_confirmation_required` cannot receive a new initial selection or switch; the principal must first amend or
re-confirm the mandate under ADR-006. An already current lane is not silently rewritten merely because its card
later supersedes, but its next call and every commitment still face the existing card-currentness checks. A
security-withdrawn current lane is immediately unusable. Selection may still move away from it to another exact,
current approved acting entry; if none exists, the case stays suspended until the principal amends or re-authorizes
the mandate under ADR-006.

The select request carries only `{check_id, expected_current_selection_id}`. Under the world lock,
authorization consumes one exact, unexpired check and re-resolves every bound fact before appending a selection
transition. A stale predecessor, replay, wrong case, changed mandate/card/policy/system-use fact, expired check,
initial non-default target, unapproved target, withdrawn card, no-op re-selection, or ambiguous authority fails
closed without changing selection.

Both write operations are authenticated only for `proc:orchestrator`, Origin-guarded, strict-body, and access-recorded.
They are classified `authorityChanging: false`: a successful transition changes which already-approved lane may
be used but is monotonically authority-narrowing: it may invalidate and release unresolved work, but cannot issue
authority, enlarge the approved set, or return a ruling, nonce, reservation, token, or output. That explicit
classification preserves ADR-002's invariant that the orchestrator reaches no authority-changing endpoint. A
later browser slice must bind the check to the dynamic case session and user gesture; this headless slice proves
that authorization supplied the exact evidence, not that a human cognitively reviewed it.

### 3. Append-only transition and observation records

A selection transition is protocol state with this bounded content:

```text
{world_id, selection_id, case_id, kind: initial | switch,
 predecessor_selection_id: id | null,
 mandate_id, mandate_version,
 target: {card_id, card_version, card_digest, requested_id, verifying_key_id},
 system_use_decision, check_id, selected_at,
 authority_effect: none}
```

The transition records the requested target before any provider call. It does not pretend a served model is
known. When a model-call terminal transaction has confirmed response evidence, authorization appends a separate
immutable observation linked by `{selection_id, call_id}` with the provider-reported `served_id`, the derived
resolution result, terminal admission/failure class, and observation time. There is no public standalone
observation writer. A materialized switch view joins transitions to observations and leaves served identity
unknown until evidence exists; it never reconstructs or upgrades it from selection state.

The requested/served evidence portion of beat 19 is satisfied only when the materialized transition contains the
requested target and at least one linked confirmed served-model observation. A selection with no completed call
remains an honest requested-only transition, not evidence that the provider served that model. Full beat 19 stays
incomplete until a later browser slice binds the transition to the case officer's user-initiated choice.

A mismatch observation does not silently select the substitute. It records the already-occurred disclosure,
withholds the output, and halts the lane under the existing beat-21 rule. Timeout or outage never causes automatic
fallback or a switch to another approved model (beat 14).

### 4. One transaction retires unresolved prior-lane work

Selection check consumption, transition append, and authorization-side invalidation are one WAL transaction.
For a switch, it:

1. invalidates every affected `issued` ruling and releases its still-reserved counters;
2. terminalizes every open prior-selection model call as `selection-invalidated`, preserving the honest
   `provider_disclosure: possible` state when no response evidence exists; and
3. appends the new selection transition last in the same operation list.

`selection-invalidated` is a distinct authorization-owned terminal reason. It is emitted only by the switch
transaction, must carry `provider_disclosure: possible` with a null served id, and is rejected on the caller-facing
`POST /model-calls/failures` request. The implementation therefore separates caller-reportable failure reasons from
the durable/internal reason vocabulary. Adding that durable reason and refinement is a substantive amendment to
the frozen M5.5 call schema; the reviewed M5.7 implementation SHA carries the schema change and its
tests explicitly. It does not weaken M5.5's rule that existing `authorization-invalidated`, malformed-response,
and tool-call-refusal failures are post-response and therefore require confirmed disclosure.

Consumed rulings, bound commitments, effects, and historical records are never rewritten. A provider response
arriving after the switch cannot be admitted because its call is terminal and its selection is stale. A held M5.4
quarantine entry from the prior selection has no release path; the headless coordinator destroys it when it
processes the successful transition, while authorization-side current-selection verification remains the safety
boundary if local cleanup is interrupted. ADR-011's proposed native wiring serializes browser selection use and
turn use under one case-local mutex, destroys predecessor quarantine before returning the switch, and projects
destroyed local custody as `discarded` rather than retained.

Allowing the orchestrator to request a switch gives that process a bounded availability lever: it can retire
unresolved work by moving among principal-approved acting entries. The risk is accepted for this headless POC,
which has no runtime caller or browser initiator, because every switch is predecessor-bound, single-use-check-bound,
non-widening, and access-recorded; no-op selection is refused. The later browser slice must bind every
production-like initiation to a case-officer gesture.

### 5. Selection identity joins model calls and gates

`selection_id` becomes protocol bookkeeping on the model-call binding, admission metadata, quarantine metadata,
server-supplied proposal model binding, and ruling binding. This prevents an `A → B → A` sequence from reviving
an old A ruling merely because the requested model id matches again.

After M5.7, model-call begin carries only `{turn_id, selection_id}`. Authorization derives the mandate/card/model
tuple from the exact current selection, rechecks the signed card and system-use decision, recomputes the provider
projection, and writes the call before returning it. Output admission rechecks that the selection is still current.
A frozen proposal must carry the server-supplied selection id and exact requested/served call evidence; ruling
issuance refuses a stale or mismatched selection. `commit-verify` lazily compares the selection binding as a
backstop to eager switch invalidation.

A selection transition itself creates no proposal, gate ruling, escalation, nonce, reservation, commit token,
commitment, effect, or permission to disclose a dropped item. The next call gets a fresh provider projection, and
any consequential proposal must pass fresh Submit and Verify rulings under the selected provider's effective
permissions.

### 6. Fixed responses and records

The check response is the exact single-card evidence projection plus its bounded check reference. The selection
response is the transition projection and counts of invalidated rulings/open calls; it exposes no internal nonce,
reservation, raw output, prompt, credential, or record payload. Access evidence contains the same bounded metadata
and digests. Card fields remain factual `self-declared` or `probe-tested` evidence—never a score, trust badge,
certification, legal approval, conformity result, or recommendation.

The reviewed M5.7 implementation deletes the old proposal-time `recordModelSelection(proposal)` API and the
served-id-bearing `model.select` WAL operation, state projection, and tests. The exported M3 deterministic
vertical-slice harness is rewired to perform the new check/select lifecycle before its synthetic provider call
and to thread the returned selection id through the new call/proposal/ruling bindings. At reviewed baseline
`6884e8c`, the repository has no `records/` directory or durable `model.select` history; the legacy op is exercised
only in temporary test roots, so the repository-supported baseline requires no replay migration. An unexpected
local legacy op fails closed as unsupported rather than being silently reinterpreted. There must be one selection
lifecycle, not two competing notions of which model is current.

## Acceptance tests for the implementation tranche

- The initial selection is derived from the mandate's explicit default; array order and software configuration
  cannot choose it.
- Approved A → B and B → A switches create distinct append-only ids, consume fresh checks, and survive exact WAL
  replay with one current selection. The fixed read recovers that selection after authorization or orchestrator
  restart without relying on client memory.
- Missing/expired/replayed checks, stale predecessor ids, no-op re-selection, unapproved models, wrong role/case,
  inactive mandates, invalid/withdrawn cards, changed policy, and changed system-use decisions fail closed.
- A switch racing model-call begin or ruling issuance has only mutex-ordered outcomes: old work completes its
  authorization transition first, or the switch retires it before it can proceed. No mixed binding is possible.
- Issued old-lane rulings are invalidated and reservations released; consumed rulings and bound effects stand.
- Open old-lane calls become `selection-invalidated` with `provider_disclosure: possible` and null served id when
  authorization has no response evidence. The durable-record schema accepts and requires that exact combination;
  the caller-facing failure request rejects the internal reason, and existing post-response invalidation still
  requires confirmed disclosure. A late served response is refused, retained nowhere, and cannot create an
  observation that authorizes use.
- Every new call, admission, proposal, ruling, and `commit-verify` rejects a stale selection id. A fresh call after
  switching recomputes the provider projection and re-arms Submit and Verify.
- Confirmed served identity is appended only from the call terminal path; provider mismatch remains detection and
  containment, never a selected fallback.
- Real-listener ACL/Origin tests cover all three new routes, access evidence, strict schemas, and the complete
  non-orchestrator denial matrix.
- The legacy helper, WAL op, state projection, and test-only history are absent. The exported M3 harness selects
  through check/select before provider use and cannot create a second lifecycle.
- `runtime:start` still creates no model-turn coordinator or provider call; the browser message route remains
  `501`; quarantine has no content reader; no conversation item or released output is produced.

## Consequences and deferred work

M5.7 makes the selected lane authorization-owned and replayable without activating it in the native runtime. It
adds protocol state and invalidation work but no new authority and no new Charter semantics; the pinned upstream
specification already requires this behaviour.

ADR-010 defines the reviewed dynamic browser-selection boundary; its bounded implementation at `ff9e438` passed
exact-SHA adversarial review with no findings. Still deferred: native provider ingress, admitted-output release and conversation
ingestion, empathy-trigger completion, general multi-case binding, live provider runs, and M6 capture. No M5.7
operation runs probes, changes keys, signs cards, or edits generated/append-only production records.
