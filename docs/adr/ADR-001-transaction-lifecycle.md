<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-001 — Transaction lifecycle (nonces, reservations, rulings, idempotency keys)

**Status:** proposed (M1). **Spec:** §4 Gate ruling, §5 Transactional core.

## Context
The authorization service is the single serialization point; commitment is two-phase (`commit-verify` → single-use short-TTL token → `effect_outcome`). The spec fixes the semantics; this ADR fixes the states.

## Questions to answer
- Exact state machines: nonce `issued → consumed | expired`; reservation `reserved → settled | released | held-for-reconciliation`; ruling `issued → consumed | invalidated | expired`; idempotency key `recorded → returned-on-retry`.
- Persistence: WAL append format, fsync policy, replay/rebuild procedure, crash-recovery order.
- Ceiling arithmetic: in-flight reservations count toward ceilings; settle at binding; failed effects stay counted until the recovery owner compensates; unbound attempts consume nothing — encode and test.
- The one-local-transaction rule on the service side (effect + idempotency outcome).

## Decision
TBD at M1.
