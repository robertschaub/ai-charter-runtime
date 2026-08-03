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
contract are pinned into the commitment before effect.

The M4 transport slice adds the deny-by-default authenticated route adapter with bounded denial evidence,
atomic single-use escalation dispositions and timeout races, orchestrator-only revised-proposal
continuation through all pre-commit gates, authorization-core-owned screening, corrected-revision retries
after a deny, enforceable substitute roles, non-overridable aggregate-ceiling contracts, counted denial
suppression, refusal events, and durable review obligations. The authorization service now boots its WAL,
policy, cards, credentials, observable-expiry sweep, and commitment reconciliation before binding a native
HTTP listener, using a closed route-to-handler table. Periodic maintenance repeats without overlapping;
ADR-003 run-start verification now precedes the run header, maintenance, and listener. The local checkpoint
detector provides the write-only composite writer, checkpoint-chain and record-chain verification,
rollback alarms, receipt references, and `npm run verify:records -- --local`; operational commit/push
anchoring remains outside this deterministic M4 slice.
The authorization-owned read model now implements fixed ruling, approved-card, mandate, routed-escalation,
verified-chain, record-verification, and applicant-extract projections behind those ACLs. Browser consoles
remain to be built.
Run `npm test` and `npm run typecheck` from the repository root.
