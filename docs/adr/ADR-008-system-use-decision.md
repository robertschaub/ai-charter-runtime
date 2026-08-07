<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-008 — Pre-ingress system-use decision

**Status:** accepted (M5.6, 2026-08-04). **Spec:** system-use decision record §§ Record shape,
Invariants, Lifecycle, Runtime integration, and first-slice acceptance tests; runtime-gates POC
specification §§1, 2, 4, 5, and 10.

## Context

Before the bounded synthetic grant workflow may use a model, authorization must resolve one current decision
covering the exact system, configuration, policy, cards, roles, data classes, purpose, and validity window.
The decision is an admissibility prerequisite only. It cannot create or widen a mandate, ruling, escalation
disposition, commitment token, effect, or assurance claim.

The decision must survive restart, refuse rollback and terminal-version reuse, and be checked at case
creation/Authorize, model-call begin, output admission, ruling and `commit-verify`, and action-record/receipt
production. The provider, orchestrator, browser, services host, and ordinary runtime callers cannot create,
select, alter, or attest it.

## Decision

### 1. Versioned schema and canonical digest

The frozen wire schema is `our-ai-charter/system-use-decision@1`. It carries the source note's exact semantic
groups: identity and scope; subject configuration; purpose; evidence references and evidence depth; decision,
conditions, unresolved findings and residual-risk disposition; validity and redecision triggers;
accountability roles; and trace metadata.

`record_digest` is lowercase SHA-256 over ADR-007 canonical JSON of the whole record with
`trace.record_digest` omitted, framed by the new `system-use-decision` domain. A digest establishes object
identity only. It does not establish truth, sufficiency, legitimacy, legal conformity, independent review,
or assurance.

The material `configuration_digest` is independently recomputed under the
`system-use-configuration` domain over canonical:

```text
{world_id, use_case_id, system_id, policy_version,
 model_cards:[{card_id, card_version, card_digest, roles}],
 data_classes, jurisdictions}
```

Arrays use deterministic unique lexical ordering; model cards are ordered by card id and version. The
configured POC system id is `ai-charter-runtime-poc`, use case is `public-grant-decision`, and jurisdiction is
`synthetic-demo`. Authorization derives policy, cards, roles, and data classes from current state and the
mandate rather than accepting them from a caller.

### 2. Lifecycle, current resolution, and append-only history

Each `(world_id, decision_id, version)` is immutable. WAL operations are closed to:

```text
proposed -> approved | approved_with_conditions | rejected
approved | approved_with_conditions -> superseded | suspended | withdrawn | expired
```

`rejected`, `superseded`, `suspended`, `withdrawn`, and `expired` are terminal for that version. A correction,
resumption, or restoration is a new successor version whose `supersedes` field names the immediately prior
version. A terminal version cannot transition again or become current. Issuing a successor never erases its
predecessor.

Current resolution is authorization-owned. Exactly one non-terminal `approved` or
`approved_with_conditions` version must match the complete material scope and be effective at the check
timestamp. Zero, more than one, a digest/integrity failure, a broken successor link, a stale scope, or a
terminal/expired state fails closed. Expiry is evaluated lazily at every boundary; a sweeper is optional and
never required for safety.

### 3. Evidence and hard conditions

Evidence depth is limited to `documented`, `evidence_observed`, `implementation_checked`,
`effectiveness_tested`, or `not_assessed`. POC provenance is limited to `synthetic_fixture`, `self_declared`,
or `probe_tested`. `not_assessed` is explicit; the schema has no independently-attested value.

Every `hard_precondition` is an id from a closed authorization-process resolver map. The first fixture uses
`synthetic-data-only` and `no-external-effect`. The production startup seam fixes both to true for the
synthetic POC. An unknown, false, or missing resolution blocks use. Free text, evidence narrative, model
output, or a caller field cannot satisfy a condition.

### 4. WAL, replay, fixture, and rollback refusal

Decision issue and transition are ordinary ADR-001 transactions inside the world lock and use the same
append/fsync/replay rules. Replay validates the record digest, version monotonicity, exact predecessor link,
transition legality, and current-version uniqueness. Any violation poisons startup rather than selecting a
plausible record.

One checked-in synthetic JSON fixture enters through an authorization-process-only startup method before the
listener binds. The method is idempotent only for byte-identical already-recorded content. There is no HTTP,
browser, provider, or orchestrator mutation route. Tests may use that same authorization-only seam with
synthetic successors; records under `records/` remain generated and are never hand-edited.

### 5. Boundary checks and ruling binding

Authorization resolves and validates the current decision:

1. before the initial mandate grant / bounded case Authorize transaction;
2. before `model_call.open` and projection disclosure;
3. again before output admission;
4. before every authority-bearing ruling and at `commit-verify`;
5. before action-record, commitment-record, effect-record, and applicant-receipt production.

The bounded reference is `{decision_id, version, record_digest, status, conditions}` where conditions contain
only sorted `{id, satisfied}` results. Model calls also bind it. ADR-001 §4's ruling tuple gains the exact
`{decision_id, version, record_digest}` reference. A decision transition eagerly invalidates issued rulings
bound to the old reference in the same world transaction. Ruling creation and `commit-verify` lazily re-resolve
the complete current decision and compare all three fields, so a missed eager sweep still fails closed.
The one exception is a terminal missing-mandate denial: it may bind `null` because it creates no case,
reservation, escalation, commitment, token, or effect. Schema refinements forbid `null` on `allow` or
`escalate` rulings and records.

ADR-012's proposed single-use model-output release adds one further use boundary. Release issue inherits the
decision bound to the admitted model call; release consumption re-resolves the complete current decision and
compares the exact bounded reference under the world lock. A transition eagerly invalidates outstanding releases,
while the consume-time check is the lazy backstop. A released conversation item is historical evidence and is not
rewritten if the decision later changes.

The system-use prerequisite is necessary and never sufficient: resolving it returns no verdict, nonce,
reservation, ruling, token, or effect capability.

### 6. M5.5 failure taxonomy and disclosure honesty

This ADR adds the distinct terminal model-call reason `system-use-invalidated`. It is a substantive amendment
to the M5.5 contract. `provider_disclosure` remains evidence-derived:

- `possible` when authorization knows a call was opened but has no evidence that model input reached a
  provider;
- `confirmed` for system-use invalidation only when authorization receives a non-null served-model id with
  the output-admission request.

Authorization durably derives that post-response failure during the admission recheck; the caller-facing
failure route cannot assert it. A pre-response invalidation remains `possible` with a null served id, and
decision state alone never upgrades it to `confirmed`. If failure reporting is interrupted, the durable open
attempt remains `indeterminate / provider_disclosure: possible`; recovery does not fabricate terminal evidence.

### 7. Projections and governance console

The principal-only read route returns a fixed allowlist: current bounded reference and currentness; exact
scope identifiers; evidence type/provenance/depth/as-of/limitations; condition ids and machine results;
validity and redecision triggers; the basis summary and unresolved-finding count; and accountability role
availability. It omits the evidence pack and rationale detail.

The route is read-only, access-logged, metadata-only, and inherits ADR-002: same authorization origin, strict
self-only CSP with `frame-ancestors 'none'`, no third-party code, cookies, or CORS, and fixed text rendering.
The UI says synthetic POC evidence and makes the absent independent challenger and remedy owner visible. It
has no mutation control, badge, colour-coded green light, aggregate score, certification result, legal or
conformity claim, or queryable trust verdict.

### 8. Records and privacy-minimal binding

Model-call/access evidence, action records, commitments, effects, and applicant receipts carry only the
bounded decision reference, condition results, and a current-at-record check result. Provider messages and
projections do not receive any decision or evidence content. Evidence packs, rationale detail, prompts,
output, provider errors, endpoints, credentials, and personal data are structurally excluded from these
projections.

An effect already bound at `commit-verify` is not rewritten if the decision later changes. Reliance may be
reopened or withdrawn through the existing Rely path. No M5.6 operation releases model output or creates a
native provider/browser ingress path.

## Consequences

The POC can demonstrate that an exact, expiring, evidence-referenced institutional decision constrained its
synthetic workflow and that withdrawal narrows future use. It cannot establish that the purpose is legitimate,
evidence sufficient, risk acceptable, authority independent, legal requirements satisfied, or remedy effective.
Independent challenger and remedy-decider roles remain absent.

This slice deliberately adds two exact-SHA review surfaces beyond new state: ADR-001 ruling binding and the
M5.5 failure taxonomy/disclosure contract. It introduces no provider/browser release, model switching, general
approval workflow, real data, key work, card signing, probe, or M6 capture.
