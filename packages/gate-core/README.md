<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# gate-core

License: AGPL-3.0-only (see ../../LICENSE.md).

M1 provides the frozen ADRs and protocol primitives: fail-closed canonicalization, domain-tagged
hashing, durable hash chains, the three-state HMAC keyring, strict integer-only schemas, and the
served-model comparator.

M2 adds the replay-complete per-world WAL and single-writer lock, deterministic YAML policy evaluator,
versioned mandate operations with eager and lazy invalidation, atomic counter/nonce/ruling issuance,
`commit-verify` with an exact effect-intent binding and pre-effect record seal, escalation-pattern
suspension, the expiry/timeout sweeper, and the pure token verifier the executing service calls before
touching its own idempotency ledger.

M3 adds server-owned signed-card verification, approved-model selection records, durable effect-outcome
adoption, and the unknown/absent crash-reconciliation transitions. The recovery owner and six-field
contract are pinned into the commitment before effect. Run `npm test` and `npm run typecheck` from the
repository root.
