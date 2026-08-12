<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-017 — Unsupported `reverse` disposition

**Status:** M6.0b definition reviewed at `2eb14ba` (2026-08-12), GO — no findings. Implementation remains
unauthorized pending separate maintainer approval. **Spec:** §4 intervention contract; §5 escalation state machine;
§7 family 9 coverage; §9 effect-specific terminal enforcement and institutional limits.

## Context

The pinned specification and its linked Charter sources include `reverse` in the general vocabulary of outcomes a
human-intervention contract may offer. They do not define one generic reversal operation. The same sources
distinguish pre-commit cancellation from post-commit reversal or compensation, require effects to be classified as
reversible, compensable, or irreversible, and ask who has authority to order restoration, refund, deletion,
correction, or compensation. The specification therefore marks post-commit reversal and compensation **not
assessed** in this POC.

The runtime currently carries `reverse` in two active allow-lists:

- `GENERAL_DISPOSITIONS` in the authorization core's intervention schema; and
- `GENERAL_CONSOLE_DISPOSITIONS` in the governance console.

No policy contract permits it, no tracked fixture or record contains it, and ADR-001's disposition map assigns it
no next-state semantics. If a future policy were to permit the existing token, the
authorization core would consume the escalation, invalidate the ruling, release reservations, create no successor
or routing obligation, and record the result. That is behaviourally indistinguishable from a terminal denial while
the operator was shown a button labelled `reverse`. This is a silent-wrong-answer state, not a fail-closed one.

Implementing generic reversal in this pre-commit escalation machine would create a larger error. A committed effect
cannot be un-settled: ADR-001 makes compensation a new gated action with its own proposal, authority, currentness
checks, commitment, service enforcement, and effect record. Whether an effect can be restored is service- and
action-specific. The POC has no remedy decider, no reversal service contract, and no post-commit reversal path.
An escalation disposition cannot manufacture any of those missing authorities or mechanisms.

## Decision

### 1. Remove `reverse` from the POC's active disposition surface

M6.0b will remove `reverse` from both active runtime allow-lists. The authorization core and governance console will
support exactly these general dispositions:

```text
allow-within-scope
deny
narrow-or-modify
seek-review
cancel
route-to-remedy
```

The dialogue disposition set is unchanged. `cancel` remains the terminal pre-commit interruption. `seek-review` and
`route-to-remedy` remain recorded routing obligations with the case parked. None claims that an already-committed
effect was restored.

This is a deliberate narrowing of the POC's implemented subset, not a redefinition of the Charter vocabulary. The
intervention contract still carries the required `permitted_dispositions` field, but this runtime accepts only
dispositions it can execute according to ADR-001. The pinned upstream specification already labels post-commit
reversal and compensation not assessed, so this removal requires no upstream edit and does not move either
provenance row. A future proposal to implement reversal must first define effect-specific semantics upstream and
then receive its own runtime ADR and review.

### 2. Unsupported input fails before it can mutate authority state

Removing the token from the authorization schema must make all of these inputs invalid:

- a policy or intervention contract whose `permitted_dispositions` contains `reverse`;
- a general-disposition HTTP request carrying `reverse`;
- a WAL transaction, escalation state, action record, or read-side projection that claims `reverse` as a
  disposition; and
- a direct core invocation that bypasses TypeScript and presents `reverse` at runtime.

The HTTP request is rejected as an invalid body before the escalation is consumed. A direct untyped core call is
rejected at its runtime input boundary before a transaction is built. In both cases the escalation stays open, its
ruling and reservations keep their prior state, the action chain is unchanged, and no successor, commitment, token,
service request, effect, or reversal claim is created.
Existing ADR-002 access logging remains in force; M6.0b adds no route and weakens no ACL or Origin check.

Policy loading and replay remain strict. An unsupported token in synthetic persisted input is an explicit schema or
recovery failure, never coerced to `deny`, `cancel`, or `route-to-remedy`. The repository contains no generated or
append-only record with this value, so no migration or record edit is authorized. Any operator-local artifact that
does contain it must halt for investigation rather than be rewritten.

### 3. The console cannot advertise an unavailable power

The governance console will remove `reverse` from its own exact allow-list. Its projection filter must omit an
unexpected caller- or server-supplied `reverse` value even if a malformed object reaches the client. No Reverse
button is rendered, and the client cannot submit that token through its typed disposition path.

The authorization service remains the authority. Console filtering is defence in depth and user-interface honesty;
it does not replace the server-side schema and core guards.

### 4. Reversal and compensation remain separately unimplemented

This correction does not add a generic undo endpoint, service-host reversal route, negative counter edit, mutable
effect record, automatic compensation, recovery shortcut, or remedy decision. It does not upgrade family 9 beyond
the already recorded partial coverage for pre-commit cancellation. A real restoration or compensating action would
be a separately authorized consequential action and would still need an effect-specific terminal enforcement
point. Irreversible effects remain irreversible and route to review or remedy rather than receiving a false
`reversed` label.

## Implementation boundary

The later implementation tranche is bounded to:

1. remove `reverse` from `GENERAL_DISPOSITIONS` and `GENERAL_CONSOLE_DISPOSITIONS`;
2. update schema, core, console, policy-validation, HTTP-boundary, persistence, and projection tests so the token is
   rejected or omitted at every named boundary;
3. preserve the behaviour and exact ordering of every remaining general and dialogue disposition; and
4. update ADR-001, README, and the implementation plan from definition candidate to reviewed implementation only
   after an exact-SHA implementation review.

It adds no route, state transition, WAL operation, record field, policy rule, authority path, Commit/effect path,
provider call, live probe, key/card operation, capture work, checkpoint operation, push, or M6.1 implementation.
Tests use synthetic objects only and never hand-edit generated or append-only records.

## Acceptance tests

The implementation is acceptable only if all of the following are proved deterministically:

1. The core and console general-disposition arrays have the exact six-token set above; `reverse` is absent from both,
   while all dialogue dispositions are byte-for-byte unchanged.
2. Intervention-contract and policy-set parsing reject `reverse`, including when it is the only permitted
   disposition or appears beside valid values.
3. The authenticated general-disposition HTTP route rejects `{ "disposition": "reverse" }` as an invalid body and
   leaves the escalation, ruling, reservation, action chain, and effect state unchanged apart from the existing
   access-log treatment of the rejected request.
4. An untyped direct-core attempt is rejected before transaction construction and does not append a refusal that
   falsely treats `reverse` as a supported disposition, consume the escalation, or release authority state.
5. Synthetic WAL, escalation, action-record, and projection objects containing `reverse` fail their applicable
   schemas or recovery boundary; no code maps the token to another disposition.
6. The console projection helper omits `reverse` from a foreign or malformed permitted list and renders no Reverse
   action.
7. Existing tests for allow-within-scope, deny, narrow-or-modify, seek-review, cancel, route-to-remedy, every dialogue
   disposition, timeout, replay, wrong role, and outside-contract disposition remain green.
8. Repository-wide production absence checks find no active `reverse` disposition in TypeScript or policy YAML;
   documentation may retain the word only to explain the source vocabulary, unsupported boundary, and honest
   coverage limit.
9. `npm run typecheck`, `npm test`, `npm run cards:verify`, and `git diff --check` pass; signed cards, provenance pins,
   generated/append-only records, and the upstream Charter repository remain unchanged.

## Consequences

The correction closes the silent terminal-denial trap and makes the UI match the runtime's actual power. It reduces
the supported POC vocabulary but adds no new authority. The cost is explicit: this prototype still cannot reverse
or compensate a committed effect, and it will reject any attempt to claim otherwise. That limit is more accurate
and safer than retaining a button and token with no defined transaction semantics.
