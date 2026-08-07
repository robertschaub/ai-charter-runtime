<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-005 — Classification inheritance (restriction tags)

**Status:** accepted (M1, 2026-08-01). **Spec:** §5 (model navigation; per-provider projections), §4 (structured proposal; screening signal; model card), §7 beats 19–21.

**Amendment (M5.1 conversation custody and projection core, 2026-08-03):** authorization durably wraps each
item in `{world_id, case_id, item}`. The wrapper is protocol scope, not model-authored content; the embedded
item shape remains the one used in frozen proposals. Dialogue transitions require an exact case/item match
against both the durable store and the frozen source proposal. Projection and tag union are implemented as
pure deterministic operations, but no provider call or case-message route is opened in this slice.

**Amendment (M5.2 authorization-resolved projections and fixture-pinned screening, 2026-08-03):** the
authorization process now resolves the active mandate, exact role approval, and freshly verified signed
card before every acting or screening projection. The acting HTTP request cannot name projection scope.
Offline screening accepts only checked-in synthetic fixture results keyed by exact frozen proposal hash and
gate, minimizes to fixture-named suspect proposal items, and revalidates the result under the world lock.
Because the bounded POC has no case-to-mandate relation, acting projection also requires exactly one active
mandate in the world and rejects ambiguity; the request's mandate reference must match that sole envelope.

**Amendment (M5.3 output admission and tag inheritance, 2026-08-04):** authorization recomputes the exact
acting projection and compares its domain-separated digest before evaluating a model result. For an admitted
result it derives `U` from every projected item and returns that sorted union as decision metadata; the caller
cannot supply case, role, items, tags, clearances, or a store operation. This slice persists no derived item and
opens no model/browser ingress, so later ingestion must consume this server-derived union without narrowing it.

**Amendment (M5.7 governed selection, reviewed at `442397a`, 2026-08-05):** ADR-009 makes one authorization-owned
`selection_id` current for the configured case. A fresh model call derives its target and recomputes its projection
from that selection; callers no longer choose the card tuple on model-call begin. A switch invalidates prior work,
and every later admission, proposal, ruling, and commitment rejects the stale selection. The headless slice still
persists no model output and opens no release consumer.

**Proposed amendment (M5.10 conversation ingestion):** ADR-012 assigns every case-officer message from a fixed
authorization-owned ingress profile and refuses it before storage/provider use unless those tags fit the current
selected acting clearance. An admitted message-bound output can enter the store only through an authorization-
issued single-use release. Authorization persists the exact call projection item ids and derived tag union, then
constructs one `inferred` item field-by-field; the orchestrator, browser, and model cannot supply or narrow tags,
provenance, store, or origin actor.

## Context
Derived content inherits the **union of the restriction tags** of its inputs — a set over confidentiality, purpose and recipient, not a scalar level. Projection to a provider is a subset check against the mandate ∩ card permissions for that provider's **role** (acting or screening); membership in the approved-model set authorizes acting, not blanket disclosure.

## Decision

### 1. Semantics: tags are requirements, permissions are clearances
A tag on an item is a **requirement the recipient must satisfy**. A provider+role holds a **clearance set**. Disclosure is permitted iff `item.tags ⊆ clearances(provider, role)`. Union therefore only ever tightens — the property the spec needs.

Clearance sets are enumerated **literally** in mandates and cards; the evaluator implements no lattice, no implication, no ordering. A provider cleared for sensitive case material lists all three `conf:` tags explicitly. This keeps the check a pure set operation and makes accidental widening impossible to express.

### 2. Closed vocabulary (POC v1)

| Namespace | Values |
|---|---|
| `conf:` | `public`, `case`, `sensitive` |
| `purpose:` | `grant-assessment` |
| `recipient:` | `officer`, `applicant`, `provider:<card-slug>` |

Grammar `namespace:value`, lowercase ASCII `[a-z0-9.-]` plus the one `recipient:provider:` sub-namespace, whose slug must name an existing card (ADR-006 slug rule). Validated by a `zod` enum + pattern. **An unknown or malformed tag fails closed**: the item becomes undisclosable everywhere and raises an integrity alarm — it is never ignored.

An item with no `recipient:` tag is receivable by anyone holding its `conf:` and `purpose:` tags. `recipient:officer` therefore keeps officer-only notes out of every model projection (no provider holds that clearance), and `recipient:provider:<slug>` pins an item to one provider.

### 3. Serialization on the four stores
Every item in `said / inferred / confirmed / permitted` carries a de-duplicated `tags` array, sorted by ADR-007's rule (JavaScript default string sort, i.e. UTF-16 code-unit order — canonicalization preserves array order, so the producer must sort). Item content is hashed, so an unsorted array would be a different digest for the same tag set.

```json
{
  "id": "inf_7", "store": "inferred", "turn": "t12",
  "text": "…",
  "provenance": { "derived_from": ["said_3", "doc_2"], "hops": [{ "requested": "gpt-5.5", "served": "gpt-5.5-2026-04-23" }] },
  "tags": ["conf:case", "purpose:grant-assessment"]
}
```

Items in `said`, `confirmed`, and `permitted` additionally carry **`origin_actor`** ∈ {`officer`, `applicant`, `document:<doc-id>`} — whose testimony, confirmation, or grant the item is, set at the entry boundary exactly like tags (never from model output). `inferred` items carry none; their standing follows `provenance.derived_from`. ADR-004's `standing_class` derivation reads this field.

Original items get their tags at the **entry boundary**, from source configuration — published criteria `conf:public`; registry reads `conf:case`; applicant-uploaded documents `conf:case` (plus `conf:sensitive` where the fixture marks it); the officer's typed notes per case default. Tags are never taken from model output.

The durable authorization state stores a case-scoped envelope around each item. Item ids are unique within
the world; replay refuses an id rebound to different content or another case. The M5.1 process startup seam
loads only the checked-in synthetic demo fixture under the authorization-process credential. No browser or
orchestrator route can seed or rewrite the store. Corrections and narrowing remove an item only from the
active materialized case view; the append-only WAL preserves the earlier value and the reason for removal.

### 4. Union propagation is turn-level
A *turn* is one model call (request→response) or one tool-output ingestion. Every item created from that turn carries `U = ⋃ tags(items in that turn's projection) ∪ tags imposed by the source`.

**Finer-grained (per-claim, per-sentence) attribution is out of scope for the POC** — and not merely for cost. Narrowing a derived claim's tags below the turn union would have to rest on the model's own account of which input it came from; model output is evidence, never authority (§4), so a model-supplied provenance claim must not be able to *loosen* a restriction. Turn-level union is the only cheap rule that cannot be talked out of a restriction.

Consequence, stated: propagation is **monotone** within a case. Declassification is only ever a human act — a `permit` disposition (ADR-004) or a principal mandate amendment introducing a new item with narrower tags — never something the system derives.

Two rules keep switching workable:
- Model output is **not** tagged with the producing provider's own `recipient:provider:` tag. Doing so would make every GPT-derived item permanently unsendable to Apertus — a one-way valve that breaks beat 19. Disclosure history is recorded as record events, not as tags; tags carry policy requirements only.
- **Lemma (no self-lockout):** every item in a projection satisfies `tags ⊆ clearances`, so the union of a projection's tags is itself `⊆ clearances`. A model's own output is therefore always re-sendable to that same model, while a switch to a less-cleared provider may legitimately drop it.

### 5. Projection at Submit and at a model switch
`clearances(P, role) = mandate.approved_models[P].data_classes ∩ card(P).declared_data_classes[role]` — the mandate governs, the card can narrow but never widen (§4). Projections are recomputed from the four stores on every Submit and every switch, **never cached per provider**, so a mandate amendment or a card update takes effect on the next projection with no invalidation problem. They are gathered before ADR-001's world lock, and the post-lock re-evaluation discards them if the mandate version, policy digest, or card digest moved underneath.

**Dropped vs blocked:**
- *Conversation-context items* that fail the check are **dropped whole** from the projection. Never truncated mid-item, never summarized down — a partial item is a new derived claim with unknown standing.
- *Material inputs and derived claims of the frozen proposal itself* cannot be dropped; hollowing out a proposal's basis while still ruling on it is exactly the silent-weakening failure. So: if another approved model **is** cleared for the missing items, Submit **denies with a Flag** naming the unmet tags — the declared safe fallback is staying on (or returning to) the cleared model, so no interruption (§5's deny-with-fallback rule). If **no** approved model is cleared, Submit **escalates → Stop routed to the principal**, since only a mandate amendment can resolve it. This split is this ADR's ruling, mirroring §5's tool-request rule; it is not stated verbatim in the spec.

Every projection records a summary in the ruling's evidence refs (no new record fields):

```json
{ "kind": "submit_projection", "provider": "openai-gpt-5.5", "role": "acting",
  "included": 24, "dropped": 3, "dropped_item_ids": ["said_9","inf_4","doc_7"],
  "unmet_tags": ["conf:sensitive"] }
```

A switch additionally invalidates all prior rulings by the §4 binding rule (acting-model id is in the binding tuple).
ADR-009 strengthens this with a selection id, because an `A → B → A` sequence must not make a ruling from the
first A current again. The switch transition and invalidation share one world-locked WAL transaction.

M5.1 implements the pure projection core and its fixed output schema: one world, one case, one card slug and
role, included whole items, and an exact summary of dropped ids and unmet tags. M5.2 wires the acting role
through an authenticated authorization route while keeping the case, role, store contents, and effective
clearance server-owned. The caller supplies only exact mandate/card approval identifiers; accepting
caller-supplied projection scope or effective clearance remains an authority bypass.
M5.3 binds model-output admission to `H_conversation-projection(projection)` and derives the turn-level union
inside authorization. The admission result has no action-authority effect and is not itself a store write.
M5.4 passes only that freshly resolved projection to a configured adapter and seals admitted bytes under the
returned server-derived union. It exposes no store-write or release consumer, so it neither persists a derived
item nor creates a path for the model or caller to narrow the inherited tags.

### 6. Screening projections
Screening carries the same tags and the same check, against the **screening-role** clearance set — permission to screen is not permission to act. Order: minimize first (the suspect input item only, not the case file), then subset-check. If the suspect item is not disclosable to any configured screening provider, no call is made and `screening_skipped: disclosure_restricted` is recorded. Because a signal can only raise and never allow, the deterministic rules simply stand — except where the policy file marks screening as **required** for that action class, in which case the missing check escalates (fail closed).

M5.2 supplies no live screening call. Its deterministic synthetic fixture set is parsed at startup and each
entry is unique by `(proposal_hash, gate)`. Authorization selects the screening provider and suspect item ids
from that exact match, requires each whole item to be canonically identical in the frozen proposal and the
active configured-case store, then resolves the current screening-role mandate/card intersection. A missing
fixture, case mismatch, item mismatch, inactive mandate, unusable card, or restricted disclosure yields
`performed: false` plus a `screening_skipped` evidence reference. The ruling stores the projection summary
and any fixture signals; a signal still cannot accompany an allow ruling. Authorization recomputes the
resolution while the world lock is held, so changed mandate/card/store evidence cannot validate a stale pass.

### 7. Revocation of a `permitted` item
Revocation removes the item and blocks it from future projections. Items already derived from it keep their (monotone) tags and are **not** retroactively deleted — deletion/retention propagation is already marked *not assessed* in the §7 family-2 coverage table, and this ADR does not quietly upgrade that claim.

## Consequences
- Projection is a pure, testable set operation with no lattice logic; fixtures can assert exact included/dropped sets per provider.
- Turn-level union over-restricts by design: a summary of one public and one sensitive input is sensitive. Accepted — the alternative depends on model self-report.
- Beats 19–21 and the per-provider Submit differences become deterministic given fixture mandates; beat 20 (unapproved model) is unaffected, it stops earlier at the entry boundary.
- The proposal schema needs `tags` on every material input and derived claim, and the mandate schema needs `data_classes` per approved-model entry per role — both feed ADR-006's card fields.
- Open for the reviewer: whether `purpose:` needs a second value to make the purpose dimension non-trivial in tests (currently only `grant-assessment`, so the namespace is exercised but never discriminating), and whether the deny-with-Flag vs escalate split in §5 should instead always escalate for auditability.
