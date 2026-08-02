<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Runtime implementation plan

**Status date:** 2026-08-02

**Current milestone:** M4 in progress; M5 is blocked.

This file tracks implementation status and sequencing in `ai-charter-runtime`. It does not replace or
reinterpret the authoritative specification. On divergence, the specification and its linked Charter
sources prevail. Specification changes are made in `our-ai-charter`, under separate maintainer approval;
the source document is linked here and is never copied into this repository.

## Specification authority and provenance

| Field | Pinned value |
|---|---|
| Canonical URL | `https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md` |
| Charter commit | `c5af1d5f54fd17db219378d1958f57832e4de878` |
| Specification path | `docs/wip/runtime-gates-poc-spec.md` |
| Immutable URL | `https://github.com/robertschaub/our-ai-charter/blob/c5af1d5f54fd17db219378d1958f57832e4de878/docs/wip/runtime-gates-poc-spec.md` |
| SHA-256 | `ce9e10b3357e8b9169d3fc2857ad3deb663a4952c55b802795fb3eb7d74fdb97` |

The provenance row changes only after an approved upstream specification change. Update the Charter commit
and digest together, verify the immutable URL resolves to the named path, and review the resulting runtime
plan change before implementation continues.

## Reviewed implementation baseline

The latest maintainer-run, cross-model adversarially reviewed runtime implementation baseline is
`2421ae9c7a59b49c8d4ea273883e1d1b89eafb1b` (`2421ae9`), with a GO verdict and no open findings.
At that baseline, `npm run typecheck` passed, the Git-safety hook suite passed 4 tests, and Vitest passed
229 tests across 22 files. The work remained unpushed at review time; branch publication remains a
maintainer decision.

## Milestone status

| Milestone | Runtime status | Evidence boundary |
|---|---|---|
| M0 — probe | Baseline artifacts implemented | Live re-probing remains approval-gated; existing evidence is not silently refreshed. |
| M1 — protocol before schemas | Implemented | ADRs, schemas, canonicalization, key handling, record chains, and authenticated-interface contracts are present. |
| M2 — transactional core | Implemented and fault-tested | Authorization remains the single durable serialization point; authority defects fail closed. |
| M3 — vertical slice | Implemented | Deterministic authorize → propose → rule → commit-verify → effect → receipt path, adapters, service ledger, and signed cards are present. |
| M4 — escalation + governance console | **In progress** | Escalation/core and native-process lifecycle are implemented; browser and read-side work listed below remains. |
| M5 — screening + empathy + switching | **Blocked** | Do not begin until M4 is complete and reviewed. |
| M6–M7 | Not started | Full capture/publication work follows the implementation milestones. |

These labels describe repository implementation status, not assurance, certification, or independent
review. Test-family coverage continues to be reported as exercised, partial, or not assessed.

## M4 completion ledger

### Implemented and reviewed

- Escalation state machine, dispositions, revision continuation, timeout races, refusal evidence, and
  single-use human intervention transitions.
- Three native OS processes over authenticated loopback HTTP, with audience-scoped credentials and exact
  child-environment custody tests.
- Strict proposal-response projection so internal bindings, nonces, evidence references, reservations,
  commit tokens, and record-entry ids do not cross into the orchestrator.
- Services-owned effect ledger and authenticated probes; startup and periodic sweep/reconciliation;
  cross-process same-boot `unknown → reconciliation-required` and new-boot `no-effect` outcomes.
- Durable authorization and services denial evidence, bounded unauthenticated suppression, and a
  method-correct negative-authorization sweep over every route denied to the orchestrator.
- Startup-window, graceful-stop, IPC-disconnect, hard-parent-death, port-release, and writer-lease lifecycle
  coverage for the native supervisor.

### Implemented in the current combined review tranche

- Authorization maintenance fail-stop coverage through a deterministic injection seam: listener closure,
  failure resolution, non-zero exit, port and clean-path writer-lease release, and no credential output.
- ADR-003 local checkpoint detection: write-only composite checkpoints, checkpoint-chain and local-chain
  verification, explicit local CLI mode, run-start rollback fail-stop before the run header or listener,
  remote-unavailability asymmetry, beat-15 tamper/rollback tests, and latest-pushed-checkpoint receipt fields.
  Synthetic tests do not commit, push, or contact a remote.

### Remaining before M4 can be called complete

1. Implement the read-side HTTP handlers behind the frozen ACLs and strict ADR-002 projections:
   ruling status; approved models; filtered mandate and escalation lists; routed escalation detail; record
   and access-chain views/verification; and the applicant's server-side scoped extract.
2. Serve the governance-console shell from the authorization origin with `frame-ancestors 'none'`, no CORS,
   strict same-origin authority-changing requests, and no third-party script or content dependency.
3. Implement the principal surfaces: mandate grant/amend/revoke, escalation inbox with only contract-permitted
   dispositions enabled, model-card check view, record/access viewer, and applicant extract.
4. Resolve the browser credential-handoff gate below before shipping a case-console session. Then implement
   the case-console model picker, authoritative dialogue deep link, two-hop outcome polling, and the HTTP-level
   raw-API bypass beat without moving authority into the UI.
5. Exercise the M4 demo beats and adversarial families named by specification §10, update honest coverage
   statements, and obtain an exact-SHA adversarial review. Only then may planning advance to M5.

## Browser credential-handoff decision gate

The headless runtime derives `ORCHESTRATOR_TOKEN_CASE_OFFICER` in memory, but no browser delivery mechanism is
specified or implemented. The case console must not ship by printing, persisting, or exposing either that
credential or the authorization-service role token.

Before case-browser implementation, the maintainer must select a narrow authorization-origin handoff. Because
that choice defines authentication, origin, and credential custody across processes, it is a normative protocol
decision: update the authoritative specification first, then align ADR-002 and ADR-004 here, and only then
implement and adversarially test it. Read-side routes and authorization-origin governance surfaces may proceed
without resolving this gate.

## Ordered next slices

1. **Combined runtime review** — one exact-SHA adversarial review of the maintenance fail-stop and ADR-003
   local detector tranche; documentation-only acknowledgements do not trigger another review loop.
2. **Read-side projections and handlers** — complete the server contract, including checkpoint/open-window
   facts required by the record viewer and applicant receipt, before building UI consumers.
3. **Authorization-origin governance console** — static shell and principal/applicant surfaces, excluding the
   unresolved case-browser handoff.
4. **Upstream handoff decision** — separately approved specification change followed by ADR alignment.
5. **Case console and M4 acceptance pass** — model picker, dialogue link/polling, raw-API beat, coverage ledger,
   and exact-SHA review.

Substantive tranches are committed and reviewed at bounded integration points. Documentation-only
acknowledgements do not trigger recursive review rounds. No tranche authorizes live probes, key generation or
rotation, model-card signing, editing generated or append-only records outside a synthetic test harness,
pushing, or starting M5.
