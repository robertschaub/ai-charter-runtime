<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-012 — Authorization-owned conversation ingestion and single-use output release

**Status:** accepted M5.10 definition at `a38d1ed`; implementation candidate awaiting exact-SHA adversarial review.
**Spec:** §3 (case console, orchestrator, and authorization service), §4 (four-store items and model-call
bindings), §5 (entry boundary, model navigation, and empathy layer), §7 beats 4 and 19–21, and §10 M5.

## Context

M5.9 can run the current authorization-owned selection over an exact authorization-produced projection. A
matching admitted response is held in process-private quarantine, but the quarantine deliberately has no reader
or release path. The case console accepts no user message, and authorization's durable conversation store changes
only through the synthetic startup fixture or a routed ADR-004 dialogue response.

Opening only the browser message route would let text reach a provider without establishing its tags, origin, and
durable case position. Opening only a quarantine reader would let admitted bytes bypass currentness checks and the
authorization-owned four-store transition. Admission is necessary but not sufficient for release: its narrow
lexical output control is not semantic clearance, action authority, confirmation, or permission.

M5.10 therefore defines one bounded conversation turn. A case officer submits one short message through a
session-bound preparation. Authorization first ingests that message as `said`; the selected model then runs over
the resulting projection; and only an authorization-issued, single-use release may ingest an admitted response as
one `inferred` item. The browser renders only an authorization-produced transcript after the durable transition.
This slice creates no proposal, ruling, commitment, effect, empathy escalation, or M6 artifact.

The release/message/version objects below are protocol bookkeeping for the specification's existing entry,
four-store, model-output-control, and model-selection semantics. They add no governance verdict or Charter field;
on any divergence the pinned specification and linked Charter sources prevail.

## Decision

### 1. The case console uses a two-step, message-bound turn

The orchestrator origin adds or activates these dynamic-session-only routes:

```text
POST /w/{world_id}/cases/{case_id}/message-preparations
POST /w/{world_id}/cases/{case_id}/messages
GET  /w/{world_id}/cases/{case_id}/conversation
GET  /w/{world_id}/cases/{case_id}/model-turns/{turn_id}
```

Both POSTs require a present Origin exactly equal to the orchestrator origin. Both GETs reject a present foreign
or opaque Origin. Every route requires the exact active case-officer session bound to the path's world and case;
static role/process credentials, handoff values, a foreign or expired session, and the headless credential fail.
No route uses cookies or emits CORS headers.

The strict preparation body is only `{message}`. The message must contain at least one non-whitespace Unicode
scalar and at most 8,192 UTF-8 bytes. The exact submitted string is retained; the boundary validates UTF-8 and
rejects control characters other than tab, carriage return, and line feed, but does not silently trim, normalize,
summarize, or rewrite it. The orchestrator stores the bytes only in a bounded process-private preparation and
returns a server-generated preparation id, message id, turn id, issue time, and expiry. It returns no message echo,
content digest, tags, projection, authorization reference, release reference, or model output.

The preparation is bound to the session id, role, world, case, authorization boot id, current selection and exact
card/model tuple. It lasts at most two minutes and no longer than the session. At most one message preparation is
held per session; replacement, logout, expiry, selection change, either process restarting, or capacity refusal
zeroes and burns the held bytes. Its id is domain-separated from ADR-010 model-selection and ADR-011 projection-run
preparations.

The strict message body is only `{preparation_id}`. Use atomically changes `issued -> consuming` before any
authorization or provider call. Replay, concurrent use, wrong session, stale boot/selection, or binding mismatch
makes no downstream call. The browser supplies no message id, turn id, store, origin actor, tag, provider, model,
mandate, system-use fact, projection, token limit, retry instruction, release reference, or authority claim.

### 2. Authorization ingests the user message before provider disclosure

The orchestrator calls one authenticated, Origin-guarded and access-recorded process route:

```text
POST /w/{world_id}/cases/{case_id}/conversation/messages
```

Only `proc:orchestrator` is allowed. The strict body is `{message_id, turn_id, text}` from the server-held
preparation.

Headers alone cannot establish whose `said` item this is. M5.10 therefore narrows the existing handoff redemption:
the orchestrator pre-generates its session id and includes it in the strict redemption request. In the same
transaction that consumes the handoff, authorization records a case-session provenance receipt bound to that
session id, the handoff's authenticated role/world/case/origin/boot evidence, and an expiry no later than 15
minutes. The orchestrator must use that same id in its local session. No browser bearer or role token crosses to
authorization, and the receipt is not returned to the browser.

Redemption refuses a proposed session id already bound to any active provenance receipt. Collision cannot replace,
merge, or select a receipt; the handoff remains unconsumed so the officer can retry the bounded exchange with a new
server-generated id.

Message ingestion treats the process-carried role/session headers only as lookup keys and requires an exact active
authorization-owned receipt; it never treats them as self-authenticating claims. Missing, mismatched, expired, or
prior-boot provenance fails before storage. Authorization records `proc:orchestrator` separately from the resolved
session provenance. The receipt is valid only for this conversation-ingress route and cannot satisfy a role-token
route or create a confirmation, permission, mandate, ruling, or other authority. A local session close immediately
blocks browser use; authorization's bounded receipt expires independently and cannot keep a closed browser session
usable.

Authorization resolves the configured case and current selection, mandate, signed card, system-use decision, and
the fixed `case-officer-message@1` ingress profile under the world lock. That profile—not the caller—assigns:

```text
store: said
origin_actor: officer
tags: [conf:case, purpose:grant-assessment]
provenance: {derived_from: [], hops: []}
```

The fixed tags must be within the selected acting lane's current mandate/card clearance. Otherwise ingestion is
refused before any store write or provider call, so the interface cannot claim a message was sent while silently
dropping it from the provider projection. The profile id and digest are durable protocol evidence; neither is an
authorization result.

In one WAL transaction authorization checks the bounded case-conversation capacity, appends the `said` item and a
message-ingress event, advances a monotonic case conversation version, invalidates unresolved case rulings and
releases their reservations, invalidates older outstanding output releases, and returns the new item id/version
plus a content digest. An unexpired open model call for the case blocks ingestion. Once its recorded TTL passes, the
call no longer blocks ingestion but remains durable indeterminate evidence: time alone does not relabel or remove
it, and only the existing selection-change path may terminalize it as `selection-invalidated`. A late result from
that call receives no release. Raw text is stored only in the authorization-owned conversation WAL/store. Action
and access records carry only ids, fixed classes, byte lengths, digests, actor provenance, and timestamps.

The case conversation version is materialized deterministically by replay: it starts at zero and advances once for
each transaction that changes the active case store, including fixture load and ADR-004 put/remove operations. Old
WAL transactions therefore establish the same version without migration or reconstruction from current contents.
Every message-bound call and release binds the exact version observed after user-message ingestion.

`message_id` is the idempotency key. A byte-identical replay under the same exact case/session/turn binding returns
the recorded result without another item, version advance, invalidation, or provider call. Reuse with different
text or binding fails closed. The browser never chooses or sees the durable store item id.

### 3. Only a message-bound call can obtain a release reference

The conversation turn uses the existing call-begin/admission lifecycle with an added process-only ingress binding:

```text
{message_id, message_item_id, conversation_version, message_digest}
```

Authorization accepts it only when it exactly names the current message-ingress result for the same case, turn,
session provenance, selection, and authorization boot. It records the case conversation version and the exact
ordered projection item ids beside the existing projection digest and item count. Call-begin then recomputes the
projection, proves that the newly ingested message is included whole, and only that returned projection becomes
provider input.

ADR-011 projection-only runs carry no ingress binding and remain permanently non-releasable. They can still prove
native provider ingress and sealed quarantine, but their admission response never includes a release reference.

When authorization admits a message-bound response, the same `model_call.complete` transaction persists the exact
server-derived projection item ids and derived tag union and issues one release record:

```text
{release_id, authorization_boot_id, call_id, case_id, turn_id,
 message_id, message_item_id, conversation_version,
 selection_id, mandate_id, mandate_version, card_id, card_version,
 requested_id, served_id, system_use_decision,
 projection_digest, output_digest, derived_tags,
 issued_at, expires_at, state}
```

The id is at least 128 random bits, the record lasts at most two minutes, and `state` is
`issued | consumed | invalidated | expired`. The full record is process-only. Browser turn status may
say only that an admitted output is `sealed-release-pending`; it exposes no release id or authorization-only
binding. A withheld, failed, malformed, substituted, tool-calling, stale, or projection-only result receives no
release record.

### 4. Release consumption and conversation ingestion are one authorization transaction

The quarantine adds one module-private consumer reachable only through the model-turn coordinator. It cannot
return raw bytes to the HTTP handler or browser. For an exact admitted, message-bound turn it sends the held content
directly to:

```text
POST /w/{world_id}/model-output-releases/{release_id}/consume
GET  /w/{world_id}/model-output-releases/{release_id}
```

Both routes accept only `proc:orchestrator`, are Origin-guarded and access-recorded, and return fixed projections.
The strict consume body is only `{content}`. No caller-supplied item id, store, provenance, tags, currentness fact,
model binding, disposition, authority, or browser session claim is accepted.

Under the world lock authorization requires an exact issued, unexpired, same-boot release and an admitted call. It
re-verifies the output digest, current case conversation version, current selection, mandate/card/model binding,
policy and system-use decision, and every persisted release field. It then constructs one item field-by-field:

```text
store: inferred
turn: release.turn_id
text: exact held content
provenance.derived_from: persisted projection item ids
provenance.hops: [{requested: release.requested_id, served: release.served_id}]
tags: persisted derived_tags
origin_actor: absent
```

One WAL transaction changes `issued -> consumed`, appends that item and a model-output-ingress event, advances the
case conversation version, invalidates unresolved case rulings and any other older outstanding releases, releases
affected reservations, and returns a content-free ingestion result. The caller cannot narrow inherited tags,
assert provenance, or write model text to `said`, `confirmed`, or `permitted`.

An exact replay of a consumed release returns the recorded content-free result without another store write. A
mismatched replay, expired or invalidated release, changed conversation, or changed authority fails closed and can
never return content. The GET is metadata-only and exists solely to resolve an ambiguous loopback response; it
cannot consume or revive a release.

The quarantine marks local consumption before transfer. A confirmed success, fixed refusal, or ambiguous transport
outcome zeroes and removes the local bytes. After ambiguity the coordinator may perform only the metadata GET: if
authorization proves consumption, the transcript is the recovery path; otherwise the output remains unavailable
and the release expires or is invalidated. Content is never retransmitted automatically, and the provider is never
called again automatically.

### 5. The browser renders only authorization-owned conversation state

The authorization service adds an authenticated process read:

```text
GET /w/{world_id}/cases/{case_id}/conversation
```

It accepts only `proc:orchestrator`, is Origin-guarded and access-recorded, and returns only the ordered active
message/output events created by this protocol. The response is bounded to 128 events and 256 KiB of UTF-8 text;
capacity is checked before ingestion and never resolved by silently dropping history. Fixture documents, dialogue
answer text, removed items, release records, tags, internal item ids, projection contents, authority bindings, and
role tokens are omitted.

The orchestrator parses that strict process projection and constructs a second browser schema field-by-field. It
contains only the public message/turn id, `case_officer | model` speaker, text, recorded time, and—for model items—
requested/served model ids plus the fixed classification `inferred-unconfirmed`. The dynamic browser session and
path are checked again before return. A new valid handoff may recover the durable transcript after an orchestrator
restart; a stale session cannot.

The case console labels model text as generated inference that has passed only the declared narrow admission
checks—not fact, advice, authorization, red-line clearance, independent review, or assurance. It provides a bounded
composer and the two-step turn gesture, but no proposal, filing, approval, confirmation, permission, or output-copy
to an authority-bearing route.

`model_interaction_available` is true only for an active dynamic case-officer session whose authorization boot is
current and whose current selected card/version/requested-model tuple has a configured native orchestrator lane.
It says only that the two-step message transport can be attempted; it is not provider health, output admission,
authority, assurance, or a promise that the next currentness check will pass.

### 6. Race, invalidation, and restart behavior

Message preparation/use, model selection, model-turn use, release consumption, session close, and transcript reads
share the existing case-local mutex. Authorization's world lock remains the safety boundary for direct process
races and durable transitions.

A selection switch racing release has only two valid outcomes: release consumes first, so the resulting inferred
item is durable and the later selection re-projects or drops it by current clearance; or the switch appends first,
invalidates the release, and the orchestrator destroys the bytes without display. Mandate/card/policy/system-use
change, conversation-version change, session end, or expiry likewise invalidates or refuses an outstanding release.
Eager invalidation is paired with the consume-time lazy recheck.

An authorization restart expires prior-boot releases before its listener binds. The existing boot mismatch closes
the browser session and destroys local preparations/quarantine. An orchestrator restart loses every local message
preparation and quarantined output but cannot erase already ingested conversation state or reconstruct an
unconsumed release. Recovery never invents content, an origin actor, a terminal release result, or a provider call.

### 7. Authority and privacy boundary

The new authorization routes mutate or read conversation evidence but are non-authorizing. They issue no mandate,
system-use decision, selection, ruling, reservation, nonce, commit token, commitment, effect, confirmation,
permission, or dialogue disposition. The orchestrator still reaches no authority-changing endpoint, and every
consequential effect still requires an executing service to verify a fresh single-use commit token.

Raw user and model text is permitted only in the bounded in-process preparations/quarantine, the exact provider
request where cleared, the authorization-owned conversation WAL/store, and the authenticated transcript response.
It is excluded from stdout/stderr, URLs, errors, access/action records, receipts, release metadata, generated
records, and test snapshots. Tests use synthetic content only.

## Acceptance tests for the implementation tranche

- Exact session/world/case and Origin tests cover all browser routes. Static, role, process, handoff, wrong-case,
  expired, closed, and prior-boot credentials fail. Strict bodies reject every caller-supplied binding or tag.
- Handoff redemption refuses a session id already bound to an active provenance receipt without consuming the
  handoff or changing either receipt. A fresh server-generated id can redeem the still-current handoff exactly once.
- Preparation enforces byte/control-character bounds, one-per-session replacement, maximum-two-minute lifetime,
  domain separation, consuming-before-dependency, replay/concurrency refusal, and byte destruction on every burn.
- Authorization assigns the fixed ingress profile; browser/process attempts to assert store, origin actor, tags,
  clearance, confirmation, permission, or authority fail. A message not disclosable to the current selected lane is
  not stored and causes no provider call.
- Message ingestion is durable and idempotent by exact message/case/session/turn binding. It advances conversation
  version and invalidates unresolved rulings atomically. Changed-content replay fails.
- An orchestrator crash after call-begin leaves an unexpired open call blocking ingestion. After the call TTL passes,
  a new message can be ingested without rewriting the old indeterminate call, and no late result obtains a release.
- Call-begin proves the new message is included whole and binds message, conversation version, ordered projection
  ids/digest, selection, mandate/card/model, system-use decision, and boot before synthetic provider disclosure.
- Projection-only, withheld, failed, malformed, substituted, tool-calling, stale, and admission-refused calls
  receive no release. Only one exact admitted message-bound call receives one short-lived release.
- Release consume rechecks every binding and derives the inferred item field-by-field from durable evidence. Exact
  replay creates no second item; changed content/currentness, expiry, invalidation, and concurrent consume fail.
- Switch/release, dialogue/message, session-close/release, authorization-restart, orchestrator-restart, and
  conversation-capacity races yield only the declared fail-closed outcomes and never expose stale bytes.
- The quarantine consumer cannot return content to an HTTP handler. Browser-visible text is byte-for-byte the
  authorization transcript item after durable ingestion, never the provider response or local quarantine buffer.
- Access/action records, logs, errors, receipts, release/status projections, and snapshots contain only bounded
  metadata and digests. Transcript projections omit fixture/dialogue/internal/authority fields and are exact-key
  tested at both process and browser boundaries.
- A lost release response causes no provider retry and no automatic content retransmission. Metadata recovery may
  prove prior consumption; otherwise the output remains unavailable and the release expires.
- Existing M5.1–M5.9 tests remain green. Tests use only synthetic loopback providers and perform no live probe,
  external model call, key operation, card signing, generated-record edit, push, empathy completion, or M6 capture.

## Consequences and deferred work

M5.10 would complete the bounded user-visible conversation transport portion of beat 19 while preserving the
selection and substitution containment of beats 20–21. It would make authorization the durable owner of every new
conversation item and make output release a single-use, currentness-checked transition rather than a quarantine
reader.

The resulting transcript is still a synthetic POC surface, not a safe-chat, factuality, legal, assurance, or
certification claim. Model output remains one coarse, turn-level `inferred` item; no model-generated sentence is
silently promoted to `said`, `confirmed`, or `permitted`.

Still deferred to separately approved slices: proposal construction from conversation state, semantic empathy
trigger completion, broader ingestion sources/roles, retention and deletion propagation, live provider runs, and
M6 capture. The present implementation candidate does not authorize another slice and is not a reviewed
integration point until exact-SHA adversarial review returns GO.
