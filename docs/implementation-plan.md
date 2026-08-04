<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Runtime implementation plan

**Status date:** 2026-08-04

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
| Publication status | Published upstream; the immutable URL resolves to the pinned path and digest |

The provenance row changes only after an approved upstream specification change. Update the Charter commit
and digest together. The required publication sequence was completed: the pinned Charter commit was
published and its immutable URL verified before the runtime M4 baseline was published. The canonical `main`
URL is a moving reference and may now serve a newer revision; reproducibility relies on the immutable URL,
commit, path, and digest above. A later upstream change does not silently move this pin.

## Reviewed implementation baseline

The latest cross-model adversarially reviewed implementation is
`b247d5b0be9bb000bfdfa08598dee772f09db309` (`b247d5b`). It closes the M5.4 review finding by making the
quarantine seal capability module-private; focused re-review returned **GO — finding closed, no new findings**.
The reviewed M5.4 tranche reproduced `npm run typecheck`, 4 Git-safety hook tests, 300 Vitest tests across
35 files, `git diff --check`, and verification of both unchanged signed cards. The published baseline remains
M5.2 at `1973515`; later reviewed commits remain local until the maintainer decides to push.

The final M4 acceptance review at `e326562f6c29fe2fc625a18127517163d5665dcd` returned **GO — M4
acceptance complete; no findings**. Review of `d25f366` had found one Medium asymmetric
disposition-route guard; the focused `7f2e153` correction was re-reviewed **GO — finding closed, no new
findings** before the acceptance tranche was added.
One separate earlier Low finding remains deliberately deferred to the anchoring-flow slice below.

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
| M5 — screening + empathy + switching | **In progress** | M5.1 is reviewed at `c1b5eb0`; M5.2 at `1973515`; M5.3 at `1cc7fb2`, with its Low wording finding closed at `2b7b45a`; M5.4 is reviewed at `b247d5b`; M5.5 durable call evidence is an implementation candidate. Runtime/browser/provider ingress remains closed. |
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

### M5.1 implemented and reviewed at `c1b5eb0` — authoritative conversation transition and projection core

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

Exact-SHA cross-model adversarial review found no code findings across the twelve requested axes and
reproduced the candidate validation: `npm run typecheck`; 4 Git-safety hook tests and 277 Vitest tests across
32 files; and both signed cards verified unchanged. The sole Low finding was the stale publication-status
wording corrected in this documentation-only follow-up. M5.1 is a reviewed integration point, not an M5
completion claim.

### M5.2 implemented and reviewed at `1973515` — authorization-resolved projections and fixture-pinned screening

- Authorization resolves the current active mandate and exact acting/screening role approval, reloads and
  verifies the signed card, and computes the mandate/card intersection internally for the configured case.
- `POST /w/{world_id}/model-projections/acting` is authenticated only for `proc:orchestrator`, read-only,
  strict-body, and access-recorded. The request cannot carry a case, role, item list, tags, or clearances.
- Screening is internal to the ruling path and minimizes to suspect proposal items selected by a checked-in
  synthetic fixture keyed by exact frozen proposal hash plus gate. The provider must have an exact screening
  role approval; the item must match the active configured-case store canonically and remain disclosable.
- Missing, mismatched, inactive, unusable, or disclosure-restricted screening returns `performed: false` and
  a typed `screening_skipped` evidence reference. Policies that require screening therefore escalate. A
  fixture signal remains escalation-only and can never create an allow.
- Projection summaries and fixture signals are stored in ruling evidence. The resolution is recomputed under
  the world lock before issue, closing the prior unconditional empty-success callback in the native process.
- Unit, real-listener, and native-process coverage exercises exact role/case resolution, whole-item drops,
  strict request rejection, disclosure access evidence, exact fixture success, changed-hash failure, and
  durable screening evidence.
- The slice makes no provider call, ingests no model output, changes no signed card, and leaves the browser
  message route at `501 model-interaction-not-active`. Switching, empathy triggers, output ingestion, and
  output red-line controls remain deferred.

The exact-SHA review of `750e380` returned two non-blocking Low findings. This focused follow-up closes both:
acting projection now rejects worlds with anything other than one active mandate and cross-checks the
request against that sole envelope, while the publicly exported M3 vertical-slice harness reports screening
unavailable instead of treating an empty result as a performed check. This is a correction to M5.2, not a
new M5 slice. Focused re-review of `1973515` returned **GO — both M5.2 Low findings are closed; no new
findings**. M5.2 is a reviewed integration point, not an M5 completion claim.

### M5.3 implemented and reviewed at `1cc7fb2` — authorization-owned output admission and red-line quarantine

- `POST /w/{world_id}/model-outputs/admit` is strict, Origin-guarded, authenticated only for
  `proc:orchestrator`, and classified as non-authorizing. It returns no ruling, nonce, token, or action authority.
- The request cannot carry case, role, items, tags, clearances, output digest, or store operations. Authorization
  injects the configured case and acting role, requires the sole active mandate, reloads the signed card, and
  recomputes the acting projection before comparing its `conversation-projection` digest.
- Requested and provider-served model ids are checked under the signed card's ADR-006 policy. Mismatch withholds;
  a benign unrecorded alias remains admitted with the factual `model_resolution_unrecorded` flag.
- The narrow English lexical POC checker withholds configured literal forms and selected variants of the two
  output-enforced red lines: claimed feeling/consciousness and need/miss/love or human-relationship replacement.
  Obvious paraphrases remain false negatives, while quoted matching text can be a false positive. `admitted`
  therefore means no configured pattern matched, not semantic red-line clearance or coverage in other languages.
- A clean decision derives the sorted turn-level union of all projected input tags inside authorization. No
  output item is persisted yet, so later ingestion must consume this union without accepting caller narrowing.
- Every completed decision appends fixed access-chain evidence containing bindings, counts, tags, reasons, and
  domain-separated projection/output digests. Raw admitted and withheld text is absent from the response,
  records, and errors.
- Exact output-digest equality with a retained `admitted` decision is necessary for any later ingress, but the
  lexical admission alone is not sufficient red-line clearance. A separately approved ingress slice must define
  the additional release policy; `withheld` always terminates the turn. M5.3 keeps the browser route closed, so
  this not-yet-implemented enforcement step is unreachable rather than optional.
- Core, ACL/schema, real-listener, and native three-process tests cover safe admission, both red lines,
  provider substitution, unrecorded benign resolution, wrong actor, stale projection, revoked authority,
  caller-added scope, foreign Origin, access evidence, and raw-output absence.
- The browser case-message route remains `501 model-interaction-not-active`; no provider is called, no output
  reaches a person or proposal, no conversation item is written, and model switching/dialogue triggers remain
  deferred. This implementation therefore does not complete M5 or exercise demo beats 4, 19, 20, or 21 end to end.

Candidate validation was `npm run typecheck` clean plus 4 Git-safety hook tests and 295 Vitest tests across
34 files, `git diff --check` clean, and both unchanged signed cards verified. Exact-SHA review found no code or
security defect and one Low documentation finding about the lexical detector's under-blocking profile. This
documentation-only follow-up states that limitation at the implementation and status surfaces; it does not alter
the reviewed gate, ADR, provenance pin, ACL, schema, projection, or safety restriction and does not require a
recursive review round.

### M5.4 implemented and reviewed at `b247d5b` — headless model-turn quarantine

- `ModelTurnCoordinator` is an orchestrator-owned library seam with no HTTP or browser route. It is not
  constructed by `orchestratorProcess`, so normal runtime startup cannot call a provider.
- A turn names only its id, current mandate/card/requested-model references, and a bounded output-token count.
  The coordinator chooses an exact configured adapter binding and refuses duplicated or mismatched lane identity
  before any projection disclosure; the caller cannot supply messages, projection items, tags, or clearances.
- Authorization re-resolves the current acting projection over its existing authenticated process route. Only
  those whole projected items enter a fixed canonical model message; dropped items remain absent.
- The provider result must contain bounded nonempty text, no tool calls, and the configured requested lane/id.
  Admission rejects non-well-formed Unicode so canonical string binding and retained UTF-8 bytes cannot diverge.
  The coordinator submits the exact content and provider-reported served id to M5.3 admission, then locally
  recomputes and compares the admission binding before retaining anything.
- `withheld`, provider substitution, revoked authority, timeout, malformed response, tool calls, binding mismatch,
  duplicate turn, or any dependency failure adds no held-buffer entry and permanently halts that lane for the
  coordinator lifetime. There is no endpoint/model fallback and no retry of the same turn.
- A clean `admitted` result is still not release clearance. The raw UTF-8 copy is held only in a process-private,
  single-assignment quarantine. Only a module-private coordinator capability can seal an entry; the exported API
  exposes fixed metadata, existence, destruction, and clear operations but no seal, content-read, or consume method.
  This is structural in-process confinement, not cryptographic authorization provenance or release approval.
  Entry-count and byte ceilings bound retention; capacity failure halts the lane. Destruction zeroes the held byte
  buffer before removal without claiming that JavaScript can erase prior immutable-string copies.
- Real-listener tests use the actual authorization HTTP routes plus a synthetic loopback OpenAI-compatible server.
  They cover filtered disclosure, sealed admission, turn replay, served-model mismatch, literal red-line withholding,
  unapproved selection before disclosure, revocation after disclosure, tool calls, malformed served evidence or
  Unicode, absence of an external seal capability, lane halt, access metadata, and raw-output absence.
- No live model is contacted; no conversation item, proposal, action authority, browser response, or generated
  record is created. Provider-failure event recording, native process wiring, model switching, dialogue triggers,
  and any output consumer/release policy remain deferred. M5 and demo beats 19–21 are not complete.

Reviewed validation is `npm run typecheck` clean plus 4 Git-safety hook tests and 300 Vitest tests across
35 files, `git diff --check` clean, and both unchanged signed cards verified. The upstream specification pin is
unchanged: M5.4 implements the existing per-provider projection and provider-substitution containment path and
adds no new governance semantics.

### M5.5 implementation candidate — durable model-call lifecycle evidence

- The authorization process removes its raw acting-projection route. `POST /w/{world_id}/model-calls/begin`
  atomically resolves the current mandate/card projection and appends a metadata-only `model_call.open` record
  before returning projected items. One case/turn has at most one durable attempt.
- The open record binds the authorization boot, world, configured case, turn, mandate/version, card/version,
  requested model, domain-separated projection digest, item count, open time, and bounded expiry. It contains no
  prompt, endpoint, credential, provider response, or caller-selected case/role/scope.
- `POST /w/{world_id}/model-outputs/admit` now requires that exact call id and output binding. Under the same world
  lock, authorization rejects expired, replayed, mismatched, or previous-boot references, re-resolves current
  authority, applies M5.3, and appends exactly one admitted or withheld terminal transition.
- `POST /w/{world_id}/model-calls/failures` consumes an open reference with one fixed class:
  `provider-timeout`, `provider-unavailable`, `malformed-response`, `tool-calls-refused`, or
  `authorization-invalidated`. Disclosure is only `possible` or `confirmed`; response-derived failures require
  confirmed disclosure, and tool-call refusal binds the served id. Raw output and provider error detail are
  structurally excluded from access and lifecycle records.
- Begin, admission, and failure are non-authorizing, Origin-guarded, access-recorded orchestrator-only routes.
  The public service surface exposes no direct acting-projection or admission method outside this lifecycle.
- The M5.4 coordinator begins the durable attempt before invoking its configured synthetic adapter. Provider and
  protocol failures attempt the fixed report, then halt the lane. If reporting is interrupted, replay retains the
  open attempt as `indeterminate / provider_disclosure: possible`; a new authorization boot cannot complete it,
  and the same turn cannot start a replacement. Recovery never fabricates success or a terminal failure.
- Focused schema, WAL/replay, ACL/Origin, real-listener, service, and coordinator tests cover exact single use,
  mismatch, expiry, restart, fixed timeout/outage metadata, raw-error absence, and non-orchestrator denial.
- This slice adds no native provider/runtime/browser entry point, model switching, dialogue trigger, conversation
  persistence, action authority, quarantine reader, or release consumer. It uses synthetic loopback providers and
  temporary record roots only. M5 and beats 19–21 remain incomplete.

Exact-SHA review of `676d4d6` found one Low custom-adapter robustness gap: a non-object value could make
malformed-response evidence derivation throw before the typed halt/report path. The focused correction makes
both response parsing and evidence derivation total. Regression coverage distinguishes the intended durable
outcomes: a successful failure report records terminal `failed / malformed-response`, while an interrupted
report leaves the attempt open and indeterminate; both paths halt the lane and return `provider-protocol`.

Correction-candidate validation is `npm run typecheck` clean plus 4 Git-safety hook tests and 305 Vitest tests across
35 files, `git diff --check` clean, and both unchanged signed cards verified. The upstream specification pin is
unchanged: this slice adds runtime provenance for the already specified model-call/disclosure boundary and does
not change the Charter specification or its governance semantics.

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

1. **Focused exact-SHA re-review of the M5.5 Low correction** — verify non-object or property-throwing custom
   adapter results cannot escape the typed halt path; successful failure reporting terminalizes with fixed
   malformed-response metadata, while reporting interruption alone preserves indeterminate state.
2. **Stop after review.** Do not add native process wiring, browser messages,
   conversation-item persistence, empathy/model switching, or any output consumer without a separately approved
   bounded slice. Any future release proposal must treat lexical admission as necessary but not sufficient.

Substantive tranches are committed and reviewed at bounded integration points. A documentation-only status
acknowledgement does not trigger a recursive review round; changes to ADRs, gates, invariants, ACLs,
projections, provenance pins, or safety restrictions are substantive and remain reviewable. No tranche
authorizes live probes, key generation or
rotation, model-card signing, editing generated or append-only records outside a synthetic test harness,
pushing, or starting an additional M5 slice.
