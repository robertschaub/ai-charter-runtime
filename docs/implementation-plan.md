<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Runtime implementation plan

**Status date:** 2026-08-03

**Current milestone:** M4 complete; M5 implementation is in progress.

This file tracks implementation status and sequencing in `ai-charter-runtime`. It does not replace or
reinterpret the authoritative specification. On divergence, the specification and its linked Charter
sources prevail. Specification changes are made in `our-ai-charter`, under separate maintainer approval;
the source document is linked here and is never copied into this repository.

## Specification authority and provenance

| Field | Pinned value |
|---|---|
| Canonical URL | `https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md` |
| Charter commit | `00c32f521d550800990c795c9a38d5a83f2daf01` |
| Specification path | `docs/wip/runtime-gates-poc-spec.md` |
| Immutable URL | `https://github.com/robertschaub/our-ai-charter/blob/00c32f521d550800990c795c9a38d5a83f2daf01/docs/wip/runtime-gates-poc-spec.md` |
| SHA-256 | `33014caab9831674225fd77d711f06065c02ee65839d278c036331e8aa27bf60` |
| Publication status | Charter commit exists locally and passed adversarial review; remote URL verification awaits a maintainer-authorized upstream push |

The provenance row changes only after an approved upstream specification change. Update the Charter commit
and digest together. Before either repository is published, push the Charter commit first under separate
maintainer approval, verify that the immutable URL resolves to the named path and digest, then publish the
runtime change. The local exact-SHA review may proceed before that publication step.
Until the upstream push occurs, the canonical `main` URL still presents the previous published revision and
must not be treated as matching this local pin.

## Reviewed implementation baseline

The latest maintainer-run, cross-model adversarially reviewed runtime implementation baseline is
`e326562f6c29fe2fc625a18127517163d5665dcd` (`e326562`). The final M4 acceptance review returned
**GO — M4 acceptance complete; no findings**. Review of `d25f366` had found one Medium asymmetric
disposition-route guard; the focused `7f2e153` correction was re-reviewed **GO — finding closed, no new
findings** before the acceptance tranche was added.
One earlier Low finding remains deliberately deferred to the anchoring-flow slice below. At this baseline,
`npm run typecheck` passed, the Git-safety hook suite passed 4 tests, Vitest passed 267 tests across 31 files,
and both signed cards verified. The branch remained unpushed at review time; branch publication remains a
maintainer decision.

**Deferred anchoring-flow finding:** remote verification currently classifies an honest failed push—where
the latest local checkpoint commit has not reached the remote—as `remote-mismatch` and fails stop. Preserve
this conservative behaviour until the operational checkpoint commit/push flow is implemented, then
distinguish an uncommitted latest checkpoint from confirmed remote rollback or mismatch.

## Milestone status

| Milestone | Runtime status | Evidence boundary |
|---|---|---|
| M0 — probe | Baseline artifacts implemented | Live re-probing remains approval-gated; existing evidence is not silently refreshed. |
| M1 — protocol before schemas | Implemented and amended | ADRs, schemas, canonicalization, key handling, record chains, authenticated-interface contracts, and the approved case-session handoff contract are present. |
| M2 — transactional core | Implemented and fault-tested | Authorization remains the single durable serialization point; authority defects fail closed. |
| M3 — vertical slice | Implemented | Deterministic authorize → propose → rule → commit-verify → effect → receipt path, adapters, service ledger, and signed cards are present. |
| M4 — escalation + governance console | **Complete** | Final exact-SHA review of `e326562` returned GO with no findings; the offline acceptance ledger preserves the remaining partial and not-assessed boundaries. |
| M5 — screening + empathy + switching | **In progress** | M5.1 implements the authorization-owned, case-scoped conversation transition and deterministic projection core while model ingress remains closed. |
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
- Authorization maintenance fail-stop coverage through a deterministic injection seam: listener closure,
  failure resolution, non-zero exit, port and clean-path writer-lease release, and no credential output.
- ADR-003 local checkpoint detection: write-only composite checkpoints, checkpoint-chain and local-chain
  verification, explicit local CLI mode, run-start rollback fail-stop before the run header or listener,
  remote-unavailability asymmetry, beat-15 tamper/rollback tests, and latest-pushed-checkpoint receipt fields.
  Synthetic tests do not commit, push, or contact a remote.

### Implemented and reviewed at `4310550`

- Fixed read-side projections and native HTTP handlers for ruling status, approved signed-card evidence,
  current mandate envelopes, role-routed escalation lists/detail, verified action/access-chain views,
  record verification with checkpoint/open-window facts, and the server-side applicant extract/local receipt.
- Defence-in-depth role filters, orchestrator-minimal escalation status, fixed leakage allowlists, durable
  record-family access evidence, in-line-tamper and same-boot valid-prefix rollback refusal against the live
  writer heads, and real-listener integration coverage.
- Authorization-origin governance-console shell with separately licensed, dependency-free static assets,
  strict self-only CSP including `frame-ancestors 'none'`, zero CORS, no cookies, token-free deep-link paths,
  and role tokens held only in that origin's `localStorage` and bearer headers.
- Principal mandate grant/amend/revoke, routed escalation inbox/detail with only open contract-permitted
  general dispositions rendered, signed model-card evidence, verified action/access record views, and the
  server-side applicant extract/local receipt surface.
- Strict text-only rendering and real-listener tests for asset routing, security headers, foreign-Origin
  refusal, principal card projection, credential absence, and preservation of the three-process authority
  boundary.

### Implemented and reviewed at `a8345f0`

Independent adversarial review returned **GO — no findings**. The reviewed validation baseline is
`npm run typecheck` clean plus 4 hook tests and 259 Vitest tests across 30 files.

- Authorization-owned, digest-only `issued`/`consumed`/`expired` handoff state bound to role, world, case,
  configured orchestrator origin, and authorization boot id; single-use redemption and expiry share the
  world's WAL serialization point, and prior-boot issued values expire before the listener binds.
- Exact same-origin runtime configuration on both origins, a user-gesture popup before mint, reciprocal
  `event.origin` plus `event.source` checks, strict one-shot messages, exact `targetOrigin`, opener severing,
  and no credential in a URL, cookie, `localStorage`, rendered output, or error message.
- Process-authenticated backchannel redemption followed by an independent orchestrator-generated browser
  bearer stored digest-only in process memory and raw only in the tab's `sessionStorage`; world/case/role
  scope, maximum lifetimes, explicit close, expiry, and orchestrator-restart invalidation are enforced.
- Unit and real-listener adversarial coverage for role, world, case, origin, target-window, boot, digest,
  expiry, replay, concurrent redemption, missing process authentication, both process restarts, static versus
  dynamic credential rejection, strict assets/configuration, and absence of raw credentials from records and
  process output.

### Implemented and reviewed through `7f2e153`

- Dynamic-session case routes expose the mandate's signed-card evidence and a case-bound ruling-status mirror;
  the static headless credential is denied, present foreign origins are refused, and the case projection never
  includes the routed question, six-field contract, answer, role credential, or evidence payload.
- The case surface implements find → check → prepare without claiming model use: the user must reveal the
  signed card before a selectable current entry can be prepared, while the browser message endpoint remains
  explicitly closed until M5.
- Authorization-origin dialogue deep links render the routed question and contract under the responder's own
  role token, then post the strict path/body-bound response directly to authorization. Wrong role,
  out-of-contract disposition, unresolved third-party evidence, foreign Origin, and terminal replay fail
  closed and are recorded.
- This M4 channel records and terminates the response transaction but deliberately mints no successor ruling
  and exposes no answer to the orchestrator. M5 must implement the server-owned said/confirmed/permitted-store
  transition and re-projection before model interaction is opened; the current `501` message boundary prevents
  a recorded dialogue disposition from being treated as model permission in the meantime.
- Third-party confirmation resolves only the exact cited synthetic registry retrieval over the services
  host's authorization-audience credential. The orchestrator is denied on that read, and only retrieval
  identity, timestamps, and content digest return to authorization.
- Unit, real-listener, and real-three-process tests cover the raw-API bypass, exact role routing, bare-confirm
  refusal, successful cited confirmation, terminal replay, zero CORS, two-hop status projection, and absence
  of answer text and credentials from public responses, records, and process output.
- Exact-SHA review of `d25f3661442fb27849c725817fcd74da54291007` found one Medium asymmetric-route
  guard: the general disposition method still accepted dialogue-only values at its core boundary. The focused
  follow-up restricts both the HTTP schema and core transition to general dispositions and adds direct-core
  and real-listener negative coverage. Independent review of `7f2e15350015f889c3d539a56001b245a555efb0`
  returned **GO — Medium finding closed; no new findings**.

### M4 acceptance implementation and review

- [The acceptance ledger](m4-acceptance.md) maps every M4 scripted beat and the §7 adversarial set to named
  executable evidence while preserving partial and not-assessed classifications.
- Beat 13 now has an explicit pre-commit cancellation case, and beat 17 has an explicit raw aggregate-ceiling
  approval attempt followed by commitment-verification refusal.
- Beat 18 now has an applicant-only, Origin-guarded challenge route and console control. The authorization
  transaction binds the contested entry to its action, appends the exact synthetic correction, marks reliance
  `withdrawn-pending-review`, and opens a single principal-owned routing obligation. It neither rewrites the
  committed record/effect nor claims an independent remedy decision.
- The real three-process test exercises that challenge after a successful effect, verifies the updated scoped
  extract, rejects duplicate opening, and includes the new authority-changing route in the orchestrator-denial
  sweep.
- Final exact-SHA review of `e326562f6c29fe2fc625a18127517163d5665dcd` returned **GO — M4 acceptance
  complete; no findings**. Validation was `npm run typecheck` clean, 4 Git-safety hook tests and 267 Vitest
  tests across 31 files, with both signed cards verified unchanged.
- Beat 15 remains honestly partial at the remote-presence boundary: local tamper/rollback and run-start
  fail-stop are exercised, but commit/push anchoring stays approval-gated and assigned to the later anchoring
  and M6 capture flow.

### M4 completion decision

The required exact-SHA adversarial review returned GO at `e326562`. M4 is complete. This closes the M4 review
cycle and permits M5 planning; it does not itself start M5 implementation.

## M5 implementation ledger

### M5.1 review candidate — authoritative conversation transition and projection core

- Authorization owns the durable, case-scoped four-store state. Its process startup may seed only the
  checked-in synthetic fixture through an authorization-process-only core seam; no HTTP route accepts store
  writes or caller-selected clearances.
- A dialogue escalation is bound to one case. `confirm`, `correct`, `narrow`, and `permit` require an exact
  case-only item reference that is both active in that case and canonically present in the frozen proposal.
  The authorization server injects its configured case binding; the orchestrator cannot select it.
- The response record, ruling invalidation, escalation consumption, and all resulting store changes commit
  in one WAL transaction. Replays and cross-case references fail closed without partial mutation.
- Conversation state keeps `said`, `inferred`, `confirmed`, and `permitted` distinct. Derived items inherit a
  deterministic monotone union of restriction tags.
- The pure provider-projection core includes only whole items whose tags are a subset of the server-resolved
  mandate/card clearance intersection and emits a fixed, deterministic included/dropped/unmet summary.
- The browser case-message route remains `501 model-interaction-not-active`. M5.1 makes no provider call,
  performs no live screening, and does not implement model switching or red-line output control.

This is an implementation candidate, not a reviewed baseline or M5 completion claim. It becomes the next
reviewed integration point only after the full local checks pass and an independent reviewer returns GO on
the exact committed SHA.

Candidate validation before commit: `npm run typecheck` passed; `npm test` passed 4 Git-safety hook tests and
277 Vitest tests across 32 files; `npm run cards:verify` verified both signed cards unchanged.

## Resolved browser credential-handoff protocol

The normative decision is pinned above at Charter commit `00c32f5`: a user-initiated authorization-origin
control mints an at-least-256-bit, single-use, maximum-30-second code bound to role, world, case, exact
orchestrator origin, and authorization boot id. An exact-origin/exact-window `postMessage` exchange carries
it without URL or persistent-storage exposure; the orchestrator redeems it over its process-authenticated
backchannel and mints an unrelated, in-memory, case-bound browser session lasting no more than 15 minutes.
Expiry, replay, concurrent redemption, binding mismatch, or either process restarting fails closed.

ADR-002 and ADR-004 freeze the route, custody, origin, and dialogue-boundary mechanics. The existing
`ORCHESTRATOR_TOKEN_CASE_OFFICER` remains only a headless synthetic-test seam: browser case routes must reject
it, and the dynamic browser session must be rejected on the headless route and every authority-bearing
authorization route. The bounded handoff and session implementation was independently reviewed at
`a8345f0` with GO — no findings.

## Ordered next slices

1. **M5.1 exact-SHA review** — adversarially verify the case/item binding, authorization-only custody,
   single-transaction transition, replay behaviour, deterministic tag propagation and projection, historical
   M4 replay compatibility, and the still-closed model-ingress boundary.
2. **M5.2 planning after GO** — define the smallest authenticated cross-process projection and deterministic
   screening slice. Keep mandate/card clearance resolution inside authorization, preserve the rule that a
   screening signal can only flag or escalate, and leave governed model switching and output red-line checks
   for separately approved slices.

Substantive tranches are committed and reviewed at bounded integration points. A documentation-only status
acknowledgement does not trigger a recursive review round; changes to ADRs, gates, invariants, ACLs,
projections, provenance pins, or safety restrictions are substantive and remain reviewable. No tranche
authorizes live probes, key generation or
rotation, model-card signing, editing generated or append-only records outside a synthetic test harness,
pushing, or starting an additional M5 slice.
