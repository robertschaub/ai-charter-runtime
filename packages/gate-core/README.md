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
are served only after their separate assets preload successfully. The governance shell uses a strict self-only
CSP, no CORS or cookies, and the principal's read-only card-evidence view does not widen mutation authority.
The M4 dialogue transaction records the routed role's direct response, refuses bare third-party confirmation
unless the cited retrieval resolves over the authenticated services boundary, invalidates the stopped ruling,
and treats replay as a recorded no-op. The orchestrator receives only ruling status; it cannot read the
question, contract, response, evidence payload, or responder identity.
The applicant challenge path binds one extract-visible record entry to its action, appends the synthetic
correction, marks reliance withdrawn pending review, and opens one principal-owned routing obligation. It
never edits the contested record or claims that the POC supplies an independent remedy decision.

M5.2, reviewed at `1973515`, resolves the current active mandate and exact role approval inside authorization,
reloads and verifies the signed card, intersects mandate and card clearances, and serves a strict
orchestrator-only acting projection for the configured case. Screening projects only fixture-named suspect
proposal items under the screening role. Fixtures are keyed by exact proposal hash and gate; absent,
mismatched, unavailable, or restricted evidence records a skipped check and required screening escalates.
M5.3, implementation-reviewed at `1cc7fb2`, adds a strict, Origin-guarded orchestrator process route that
recomputes the current acting projection before admitting model output. Served-model mismatch or a configured
lexical match for either output-enforced empathy red line withholds the output; obvious paraphrases can remain
undetected, so a clean admission is not semantic red-line clearance. Every result has `authority_effect: none`.
The access chain receives bindings, counts, tags, reasons, and domain-separated digests, never raw model text.
The native process makes no model-provider call and the browser message route remains closed.
Run `npm test` and `npm run typecheck` from the repository root.
