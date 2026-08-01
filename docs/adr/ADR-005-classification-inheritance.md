<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-005 — Classification inheritance (restriction tags)

**Status:** proposed (M1). **Spec:** §5 (model navigation; per-provider projections).

## Context
Derived content (summaries, inferences, quotations) inherits the **union of the restriction tags** of its inputs — a set (confidentiality, purpose, recipient), not a scalar level. Projection to a provider is a subset check against the mandate ∩ card permissions for that provider's role.

## Questions to answer
- The POC tag vocabulary (small, closed set) and its serialization on items in the four stores (said / inferred / confirmed / permitted).
- Union propagation rules through model output (everything derived in a turn inherits the turn's input union — or finer-grained attribution?).
- The subset check at Submit re-projection on model switch; what is dropped vs blocked.
- Interaction with screening projections (minimized inputs still carry tags).

## Decision
TBD at M1.
