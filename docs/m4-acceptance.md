<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# M4 acceptance ledger

**Status date:** 2026-08-03

**Maturity:** maintainer-run implementation evidence, not independent assurance or certification

**Scope:** offline, deterministic M4 acceptance; no live model probe, key operation, card signing, remote push,
or generated-record edit

This ledger maps the M4 delivery row in the authoritative specification to executable repository evidence.
It does not upgrade partial or unassessed coverage. Independent exact-SHA adversarial review of
`e326562f6c29fe2fc625a18127517163d5665dcd` returned **GO — M4 acceptance complete; no findings**.

## M4 scripted beats

| Beat | Status | Executable evidence and boundary |
|---|---|---|
| 0 — bounded mandate grant | **exercised** | The real three-process test grants the signed-card-bound mandate through the principal HTTP route, refuses a foreign Origin, and reads back only the fixed projection ([processBoundary.test.ts](../packages/consoles/src/processBoundary.test.ts)). The console mutation client remains a thin authorization-origin caller. |
| 3 — conflicting records and narrowing | **exercised** | The named headless test runs Verify escalation, case-officer narrowing, a fresh proposal revision through Authorize → Submit → Verify, then commitment, effect, and outcome ([m4EscalationSlice.test.ts](../packages/consoles/src/m4EscalationSlice.test.ts)). |
| 10 — privilege expansion | **exercised** | Core tests deny broadened authority, refuse orchestrator mandate mutation, require the principal's separate versioned amendment, and re-rule human approval instead of treating it as authority ([authorizationCore.test.ts](../packages/gate-core/src/authorizationCore.test.ts)). |
| 11 — timeout | **exercised** | Timeout atomically applies the declared safe default, invalidates the ruling, releases reservations, and records a later disposition as a no-op ([authorizationCore.test.ts](../packages/gate-core/src/authorizationCore.test.ts)). |
| 13 — pre-commit cancellation | **exercised** | The explicit cancellation test consumes the escalation, invalidates the uncommitted ruling, creates no commitment, and retains the contract's named recovery owner in the recorded intervention path ([authorizationCore.test.ts](../packages/gate-core/src/authorizationCore.test.ts)). |
| 15 — tamper and rollback | **partial** | In-line tamper, valid-prefix rollback, checkpoint/pointer alteration, run-start fail-stop, and verified-read refusal are exercised ([checkpoint.test.ts](../packages/gate-core/src/checkpoint.test.ts), [authorizationReadSide.test.ts](../packages/gate-core/src/authorizationReadSide.test.ts)). An actual commit/push and remote-presence demonstration is approval-gated and remains in the later anchoring/capture flow. |
| 16 — applicant extract and local receipt | **exercised, local boundary** | The real authorization listener returns the server-side scoped extract and local receipt, excludes internal bindings, and logs the read. A remotely confirmed checkpoint is projected when one exists; the deterministic run truthfully returns `null` ([processBoundary.test.ts](../packages/consoles/src/processBoundary.test.ts)). |
| 17 — above-ceiling human approval | **exercised** | The raw core client attempts `allow-within-scope` on an aggregate-ceiling escalation; the contract refuses it, commitment verification rejects the non-allow ruling, and no commitment exists ([authorizationCore.test.ts](../packages/gate-core/src/authorizationCore.test.ts)). |
| 18 — applicant factual challenge | **exercised** | The real three-process path posts under the applicant token, appends the exact synthetic correction, marks reliance `withdrawn-pending-review`, opens one principal-owned routing obligation, exposes it in the applicant extract, and rejects duplicate opening ([processBoundary.test.ts](../packages/consoles/src/processBoundary.test.ts)). No independent remedy decider or resolution is claimed. |

The M4-frozen transport portion of beat 4 is also exercised: direct authorization-origin response, exact
role and contract routing, evidence-backed third-party confirmation, bare-assertion refusal, Origin refusal,
and terminal replay. The said/confirmed/permitted stores, correction re-projection, screening triggers, and
model interaction remain M5 and are not counted as an exercised beat-4 outcome.

## Adversarial set

| Set | Status | Evidence |
|---|---|---|
| Bypass, replay, proposal/ruling mismatch, mutation after allow | **exercised** | Authorization-core, services-ledger, authenticated-adapter, and real three-process tests. |
| Mandate ordering, mid-flight revocation/policy change, counter race | **exercised** | Serialized core tests cover both linearization orders and exactly-one counter reservation. |
| Late approval, crash reconciliation, illegal lifecycle transitions | **exercised** | Core, services-host, WAL replay, process fail-stop, and supervisor lifecycle tests. |
| Intervention contract | **exercised** | Six-field schema refusal, wrong role, unauthorized substitute, outside-set disposition, dialogue/general-route separation, and concurrent single-use disposition tests. |
| Case-session handoff | **exercised** | Exact origin/window/source/world/case/role/boot bindings, expiry, replay, concurrent redemption, missing process authentication, both restart cases, and authority-route confinement are covered at unit and real-listener layers. |
| Subdelegation | **not exercised** | The scenario remains single-agent; schema support is not runtime evidence. |

## Test-family status carried forward honestly

- Families 3, 5, 6, 7, and 10 are exercised with the specification's stated gaps: stale memory, additional
  injection vectors, retention, and custodian failure are not implied.
- Families 2, 8, 9, 11, and 12 remain partial. Post-commit reversal/compensation, retention/deletion
  propagation, export/exit, and production outage behavior are not assessed.
- Family 4 is not assessed. Families 1 and 13 are not applicable or not assessed for this non-ambient,
  non-production interface.
- The zero-tolerance consequential-effect invariant is exercised at the `commit-verify` linearization point.
  The documented short token-TTL residual is not recharacterized as eliminated.

## Acceptance outcome

All offline M4 implementation paths named above are exercised. Remote anchoring presence remains explicitly
partial and approval-gated; M6 still owns the all-beats capture. The exact-SHA review gate is satisfied at
`e326562f6c29fe2fc625a18127517163d5665dcd`: M4 is **complete**, and M5 is unblocked for planning but has not
begun.

Reviewed validation: `npm run typecheck` clean, 4 Git-safety hook tests, 267 Vitest tests across 31 files,
and both signed model cards verified unchanged.
