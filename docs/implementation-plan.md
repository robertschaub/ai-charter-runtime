<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Runtime implementation plan

**Status date:** 2026-08-08

**Current milestone:** M4 complete; M5 implementation is in progress.

This file tracks implementation status and sequencing in `ai-charter-runtime`. It does not replace or
reinterpret the authoritative specification. On divergence, the specification and its linked Charter
sources prevail. Specification changes are made in `our-ai-charter`, under separate maintainer approval;
the source document is linked here and is never copied into this repository.

## Specification authority and provenance

Both governing sources are pinned to the same reviewed Charter commit. A cross-link from one source to the
other is not a provenance pin; both paths and byte digests are verified independently.

| Source | Path | SHA-256 | Immutable URL |
|---|---|---|---|
| Runtime-gates POC specification | `docs/wip/runtime-gates-poc-spec.md` | `4e52e02115dacbaaf782a999ecc1aeb05c9a3d99ba5f53cdd76998b0c205e5f5` | `https://github.com/robertschaub/our-ai-charter/blob/51b408c5f1bad929fbf0a27599689857130817a3/docs/wip/runtime-gates-poc-spec.md` |
| System-use decision record | `docs/wip/system-use-decision-record.md` | `ea4342c16221687c33bffb6ca3a4d94f267ce98e3d18880bacc08316278e0a84` | `https://github.com/robertschaub/our-ai-charter/blob/51b408c5f1bad929fbf0a27599689857130817a3/docs/wip/system-use-decision-record.md` |

Shared Charter commit: `51b408c5f1bad929fbf0a27599689857130817a3`. Publication status: both immutable
URLs resolve to the named path and independently verified digest.

This pin moves from `6a52bd9` because the published runtime specification added two explicit honest-limit
paragraphs: effect-specific terminal enforcement and the representation-error ambiguity in the pattern counter.
The system-use source is byte-identical; its row moves only to keep both governing sources on one Charter commit.
Neither upstream change supplies or pre-approves ADR-012's protocol mechanics.

The provenance rows change only after an approved upstream specification change. Move both source pins in
one runtime commit, even when only one source changed, and re-verify both byte digests against the shared
Charter commit. The canonical `main` URLs are moving references; reproducibility relies on the immutable
URLs, commit, paths, and digests above. A later upstream change does not silently move either pin.

## Reviewed implementation baseline

The latest cross-model adversarially reviewed implementation is
`8a904f37bdee7b8f083ca92d35f6db474c14d8e2` (`8a904f3`). Exact-SHA review of the bounded M5.10 conversation
ingestion and single-use output-release implementation returned **GO — no blocking findings**. Validation reproduced
`npm run typecheck`, 4 Git-safety hook tests, 357 Vitest tests across 41 files, `git diff --check`, and verification
of both unchanged signed cards. That implementation and review did not move the Charter provenance baseline.
The published runtime head is `5fdf79bb90aa4aa185ff6af5792d155e02f13d46` (`5fdf79b`). It contains the
reviewed M5.3–M5.10 integration range and the documentation-only M5.10 review closure. The M5.11 definition
candidate below is local, unreviewed, and unimplemented.

The M5.9 definition at `2a508ba7500d6f0775e4cb52b63a7ac222066f64` received one focused browser-redaction
finding. Commit `be01667d169beb918ec4ceffb384edb8a526020e` bound field-by-field construction and exact-key
tests in both selection states; focused re-review returned **GO — finding closed; no new findings**. The bounded
implementation at `e58d397c38ff00fe86f4c363cdb6dbcae9f707ed` then received **GO — no findings**.

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
| M5 — screening + empathy + switching | **In progress** | M5.1 is reviewed at `c1b5eb0`; M5.2 at `1973515`; M5.3 at `1cc7fb2`, with its Low wording finding closed at `2b7b45a`; M5.4 at `b247d5b`; M5.5 durable call evidence at `1d992fa`; M5.6 system-use decisions at `b57c01e`; M5.7 headless governed selection at `442397a`; M5.8 browser initiation at `ff9e438`; M5.9 native provider ingress at `e58d397`; and M5.10 conversation ingestion and output release at `8a904f3`. M5.11 governed proposal intake is a review-pending definition only. Empathy-trigger completion and M6 remain incomplete. |
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

### M5.5 implemented and reviewed at `1d992fa` — durable model-call lifecycle evidence

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
Focused re-review of `1d992fa` returned **GO — M5.5 Low custom-adapter robustness finding closed; no new
findings**. M5.5 is therefore a reviewed integration point, not an M5 completion claim.

Reviewed validation is `npm run typecheck` clean plus 4 Git-safety hook tests and 305 Vitest tests across
35 files, `git diff --check` clean, and both unchanged signed cards verified. The upstream specification pin is
unchanged: this slice adds runtime provenance for the already specified model-call/disclosure boundary and does
not change the Charter specification or its governance semantics.

### M5.6 implemented and reviewed at `b57c01e` — system-use decision prerequisite

- Authorization owns a versioned, digest-bound, append-only system-use decision lineage. Startup loads one
  checked-in synthetic fixture through a `proc:authz`-only seam; no HTTP or browser mutation route exists.
- Exact world, use case, system, material configuration, policy, signed-card versions/digests/roles, data
  classes, jurisdiction, validity, status, integrity, and hard conditions are resolved internally. Callers
  cannot select or override decision facts or currentness.
- Mandate/case creation, model-call begin and output admission, authority-bearing ruling issuance,
  `commit-verify`, and record/receipt production bind or recheck the bounded decision reference. Terminal
  transition eagerly invalidates issued rulings and releases their reservations; lazy reads and
  `commit-verify` remain backstops. A pre-mandate terminal denial records a null reference and creates no use
  or authority; allow/escalate records may not.
- The M5.5 failure vocabulary adds the distinct terminal class `system-use-invalidated`.
  Disclosure stays evidence-derived: a post-provider admission refusal records `confirmed`; decision state
  alone never upgrades an indeterminate open call.
- Model-call/access evidence, action records, commitments, effects, applicant extracts, and local receipts carry
  only bounded reference/condition/current-at-record facts. Evidence packs, detailed rationale, prompts,
  outputs, provider errors, endpoints, credentials, and personal data remain structurally excluded.
- A principal-only, access-logged, read-only governance projection shows currentness, exact binding, evidence
  depth/provenance/limitations, hard conditions, validity, and absent accountability roles. It inherits the
  strict self-only CSP, `frame-ancestors 'none'`, no third-party code, no cookies, and no CORS; it exposes no
  mutation, badge, score, certification, legal approval, conformity result, or action authority.
- Dedicated tests cover inactive/expired/integrity-invalid state, every exact-scope mismatch, unmet conditions,
  authorization-only fixture loading, successor replay and rollback refusal, grant and ruling boundaries,
  eager invalidation, pre-commit prevention, post-call invalidation with no quarantine/conversation persistence,
  disclosure honesty, bounded projection privacy, console content, ACL, and access logging.

The initial exact-SHA review at `da548b2` returned **NO-GO** on three bounded findings: the caller could assert
confirmed disclosure for system-use invalidation, record-time currentness was reconstructed rather than captured,
and the README understated native runtime wiring. The correction at `b57c01e` derives confirmed disclosure only
from a served output-admission request, computes currentness when each record is authored, and states the runtime
boundary accurately. Focused re-review returned **GO — findings closed, no new findings**.

Reviewed validation is `npm run typecheck` clean plus 4 Git-safety hook tests and 319 Vitest tests across
36 files, `git diff --check` clean, and both unchanged signed cards verified. M5.6 adds no live provider,
browser-message, output-release, model-switching, or M6 path and does not complete M5.

### M5.7 implemented and reviewed — headless governed model selection and switching

Exact-SHA review of the definition correction at `4611843` returned **GO — both findings closed, no new
findings**. ADR-009 therefore froze this implementation boundary against the already pinned specification.
The implementation at `442397a` has now received exact-SHA adversarial review with **GO — no findings**:

- The mandate gains one explicit default acting-model reference; array order and software configuration cannot
  select a default.
- Authorization supplies a boot-bound, maximum-five-minute, single-use check over one exact current signed-card,
  mandate, and system-use binding. A separate orchestrator-only operation consumes it to append an initial
  selection or switch for the configured case.
- A fixed current-selection read supports restart recovery. The read, check, and select process routes are
  Origin-guarded, access-recorded, and non-authorizing; the writes are strict-body. They cannot change the approved
  set or return a ruling, nonce, reservation, token, output, or other action authority.
- A successful switch atomically invalidates affected issued rulings, releases reservations, and terminalizes
  open prior-selection calls as the distinct `selection-invalidated` class with evidence-derived `possible`
  disclosure when no response evidence exists. Only the authorization-owned switch transaction may emit it; the
  caller-facing failure request rejects it. This explicit M5.5 durable-schema/refinement amendment leaves the
  existing post-response `authorization-invalidated` rule unchanged. Bound commitments and effects stand.
- `selection_id` joins model calls, admission/quarantine metadata, proposals, rulings, and `commit-verify`.
  Fresh calls derive their model/card tuple from current authorization state, recompute the provider projection,
  and re-arm Submit and Verify. An `A → B → A` sequence cannot revive an old A ruling.
- Requested selection is recorded before a provider call. Served identity is appended only from confirmed
  model-call evidence; mismatch is containment evidence and never an automatic fallback.
- The implementation deletes the legacy proposal-time `recordModelSelection(proposal)` API and `model.select`
  WAL/state meaning. It rewires the exported M3 deterministic harness through check/select before provider use;
  the reviewed baseline contains no durable legacy history requiring replay migration.

This implementation adds no upstream governance semantics: runtime specification §5 and beats 14 and 19–21
already require it, so the Charter provenance pin stays unchanged. The reviewed implementation adds no browser
selection, native provider ingress, output release, conversation ingestion, live probe, or M6 path. Reviewed
validation is `npm run typecheck` clean plus 4 Git-safety hook tests and 326 Vitest tests across 36 files,
`git diff --check` clean, both unchanged signed cards verified, and both pinned Charter digests recomputed.

### M5.8 implemented and reviewed at `ff9e438` — browser-initiated governed selection

ADR-010 defines the bounded browser bridge from the existing dynamic case session to the reviewed M5.7
authorization protocol. It adds no upstream governance semantics and does not move the Charter provenance pin:

- The orchestrator origin exposes a redacted current-selection mirror and a two-step preparation/use protocol only
  to an exact active case-officer session. Static headless, role, process, handoff, wrong-case, and expired
  credentials are refused; both mutations require a present exact same Origin.
- Preparation accepts only the public target. The orchestrator derives current selection, asks authorization for a
  fresh check, and keeps the check id and predecessor process-private. The browser receives exact refreshed card
  evidence plus an unrelated, session-bound preparation lasting at most two minutes.
- Selection accepts only that preparation id. It is marked consuming before the authorization call, used once, and
  burned on definite refusal or ambiguous dependency outcome. Recovery reads authorization's current selection;
  no automatic retry or fallback is permitted.
- Authorization continues to authenticate `proc:orchestrator`. Server-derived role/session headers are recorded as
  claimed provenance only and have no code path into mandate, card, policy, system-use, ruling, or commitment
  decisions.
- Browser projections redact authorization check ids and internal bindings. The existing local-only model-choice
  storage is removed; current state is never inferred from DOM state, storage, array order, or software defaults.
- The slice ends after the durable selection transition. `/messages` remains `501`, model interaction remains
  unavailable, and no provider call, conversation item, output release, empathy transition, probe, or M6 path is
  added.

Exact-SHA adversarial review of the definition at `85fef1f` returned **GO — no findings**. It independently reproduced
`npm run typecheck` clean, 4 Git-safety hook tests and 326 Vitest tests across 36 files passing,
`git diff --check` clean, both unchanged signed cards verified, and both Charter digests. The review accepts only
the contract.

The reviewed implementation realizes that contract without changing the Charter pin or opening a model
ingress. It retains the handoff and authorization boot bindings in the in-memory session, keeps at most one
two-minute preparation per session, marks use consuming before the dependency call, burns it on every terminal or
ambiguous outcome, and exposes only redacted model evidence/current-transition projections. The console removes
the old storage marker and separates evidence review from selection. Unit, HTTP-route, and real-listener coverage
exercise strict bodies, exact Origin/session confinement, two-session races, A → B → A identities, on-behalf
provenance, ambiguous failure, authorization/orchestrator restart, and the still-closed provider/message/release
paths. Exact-SHA adversarial review of `ff9e438` returned **GO — no findings** and reproduced `npm run typecheck`,
4 Git-safety hook tests and 331 Vitest tests across 37 files, `git diff --check`, both unchanged signed cards, and
both Charter digests. No probe, key operation, card signing, generated-record edit, provider call, or push was
performed.

### M5.9 implemented and reviewed at `e58d397` — native provider ingress to sealed quarantine

ADR-011's definition and focused correction were reviewed at `2a508ba` and `be01667`; the correction review returned
GO with no open finding. The bounded implementation at `e58d397` does not move the Charter provenance pin and
implements this path:

- A dynamic case session receives a two-step, maximum-two-minute preparation/use protocol for one run of the
  current authorization-owned selection. The browser supplies no message, prompt, turn/model/selection binding,
  projection content, tag, authority fact, or retry instruction.
- The native orchestrator constructs both reviewed OpenAI-compatible lanes before binding. The supervisor gives
  lane keys and endpoint/model configuration only to that child; endpoint, lane, requested id, and token parameter
  must match the current signed card. Configuration never selects a model and startup itself makes no provider
  request; loopback adapters enter only through a non-runtime test seam.
- Authorization's existing call-begin transaction remains the only provider-input source and records the exact
  selection/system-use/projection binding before disclosure. Output returns directly to authorization admission;
  no failure, timeout, or mismatch triggers a retry or fallback.
- Browser use/status responses are bounded metadata with branch-derived `none | possible | confirmed` disclosure.
  Admitted bytes remain sealed behind the existing no-reader quarantine; withheld and failed bytes are destroyed.
- Selection use and turn use share a case-local mutex. A switch, session close, or expiry destroys affected held
  bytes and projects `discarded` rather than claiming a quarantine still exists.
- `/messages` remains `501`, `model_interaction_available` remains false, and there is no user-message or model-output
  conversation ingestion, output release, proposal construction, empathy completion, live call, probe, or M6 path.

Exact-SHA adversarial review returned **GO — no findings** and reproduced `npm run typecheck`, 4 Git-safety hook
tests, 344 Vitest tests across 40 files, `git diff --check`, and verification of both unchanged signed cards. Tests
use synthetic adapters/fixtures only; no live provider call, probe, key operation, card signing, generated-record
edit, push, output release, or M6 work was performed.

### M5.10 implemented and reviewed at `8a904f3` — conversation ingestion and single-use output release

ADR-012 defines the bounded M5.10 contract. It moves both Charter provenance rows to the published `51b408c`
baseline. The reviewed implementation realizes only this path:

- A case-session-only, two-step message preparation/use accepts one bounded case-officer message. Authorization
  assigns the fixed ingress profile, persists it as `said`, advances a case conversation version, and invalidates
  unresolved rulings before any provider call.
- Only a message-bound call can receive an admission-issued, boot-bound, maximum-two-minute release. Projection-only
  M5.9 runs and every withheld/failed/stale result remain non-releasable.
- Release consumption rechecks conversation version, selection, mandate/card/model, policy, system use, projection,
  output digest, and inherited tags under the world lock. It atomically persists one `inferred` item and consumes
  the release; caller fields can create neither provenance nor authority.
- The quarantine transfers held bytes only to authorization through a module-private consumer and never returns
  them to the browser handler. After durable ingestion the browser renders only an authorization-owned, exact-key
  transcript labelled `inferred-unconfirmed` for model text.
- Message/release mutations share the existing case-local mutex with selection and model-turn use. Eager
  invalidation plus consume-time recheck closes switch, system-use, mandate/card/policy, session, and restart races.
- Proposal construction, dialogue-trigger completion, broader ingestion, retention/deletion propagation, live
  provider runs, and M6 capture remain closed.

Exact-SHA review of the initial definition at `cb7d136` returned **NO-GO** on two bounded contract gaps: an expired
but durably open call could permanently block later ingestion, and ADR-010/ADR-011 still carried unqualified M5.8
and M5.9 statements that `/messages` remained unavailable and the browser never received model text. The focused
correction makes only unexpired open calls block ingestion, preserves expired calls as indeterminate evidence while
forbidding late release, adds the missing amendment notes, and refuses collisions with active session-provenance
receipts. Focused exact-SHA re-review of the correction at `a38d1ed` returned **GO — both findings closed; no new
findings**. The maintainer then approved the bounded implementation slice.

The implementation adds durable session-provenance receipts and replayable conversation/release state;
authorization-only ingress, consume/status and transcript routes; exact message/call/release binding; eager
invalidation plus consume-time recheck; module-private quarantine transfer; and a dynamic-session-only browser
preparation/use/transcript flow. Projection-only M5.9 calls remain sealed with no release path. It creates no
proposal, ruling, commitment, effect, empathy completion, live probe, or M6 artifact.

Exact-SHA adversarial review of `8a904f3` returned **GO — no blocking findings** and reproduced `npm run typecheck`,
4 Git-safety hook tests, 357 Vitest tests across 41 files, `git diff --check`, and verification of both unchanged
signed cards. The tests include real authorization/orchestrator listeners and synthetic loopback providers; they cover
strict session/origin boundaries, provenance collision, bounded byte custody, exact replay, expired indeterminate
calls, post-issue invalidation, and status-only recovery after a lost consume response. This is implementation
evidence, not assurance or certification.

The reviewer recorded two non-blocking hardening observations: the replay transaction-shape validator does not
explicitly cap conversation events to one per case per transaction, and it enforces provenance-issue-with-consume
but not the reverse pairing. Neither shape is emitted by an implemented composer; the first requires a forged WAL,
and the second fails closed by leaving the resulting browser session unable to ingest. They are deferred rather
than changing the exact reviewed implementation.

### M5.11 definition candidate — governed proposal intake and fixed pre-commit gates

ADR-013 proposes the next bounded bridge from the reviewed M5.10 conversation to the existing proposal/gate core.
It is a definition only and has not received exact-SHA adversarial review or implementation approval:

- A dynamic-session-only, empty-body proposal preparation binds one explicit user gesture to the current
  authorization boot, conversation version, selection, signed-card model tuple, and case-session provenance.
- A mutually exclusive proposal-purpose call uses only authorization's exact non-empty acting projection, the
  signed card's probe-tested native JSON-schema capability, no tools, and a fixed 512-token ceiling. It receives
  neither a conversation release nor a projection-only quarantine disposition.
- Admission may issue one short-lived proposal intake. Authorization consumes its quarantined bytes once, rejects
  duplicate-key or non-schema JSON, resolves only exact active projection item ids, and constructs the existing
  frozen proposal field-by-field with server-derived provenance and authority bindings.
- A proposal-origin sidecar preserves the exact conversation/call/projection/model/system-use/policy binding
  without adding governance-semantic fields to the specification's proposal schema.
- A fixed empty-body precommit operation runs only Authorize → Submit → Verify over the stored proposal,
  stopping on deny, escalate, stale state, or ambiguity. It cannot run Commit, reserve counters, mint a token,
  call a service, or produce an effect.
- The browser receives only an exact-key proposal and gate-evidence projection. Raw provider JSON, internal store
  ids/tags/provenance, transport/authority bindings, credentials, tokens, and provider errors remain excluded.
- Semantic dialogue-trigger routing/revision, dynamic-session Commit/effect initiation, broader ingestion,
  retention/deletion propagation, live providers, and M6 capture remain separate and unapproved.

This ordering is deliberate: M5.1's dialogue response requires an active item canonically present in a frozen
proposal. Implementing the trigger first would leave the native flow dependent on a caller-carried fixture
proposal. The proposal remains model evidence, never authority; authorization still decides every gate and a
future executing service must independently verify a single-use Commit token.

## Resolved browser credential-handoff protocol

The normative decision is pinned above at Charter commit `51b408c`: a user-initiated authorization-origin
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

1. **Adversarially review the M5.11 definition at one exact committed SHA.** Verify its Charter trace, separation
   from M5.10 conversation release, authorization-owned proposal construction, fixed precommit order, browser
   redaction, replay/currentness rules, and unchanged M5.1–M5.10 behavior.
2. **Close any definition finding before implementation.** A correction remains documentation-only; do not mix it
   with schemas, routes, WAL operations, UI, provider activity, or another M5 slice.
3. **Implement M5.11 only after the definition returns GO and the maintainer separately approves implementation.**
   Commit one bounded candidate for exact-SHA code review. M5.12 dialogue-trigger completion remains separate.
4. **Do not begin M6.** Live dual-model capture remains gated on the remaining reviewed M5 work and explicit
   approval.

Substantive tranches are committed and reviewed at bounded integration points. A documentation-only status
acknowledgement does not trigger a recursive review round; changes to ADRs, gates, invariants, ACLs,
projections, provenance pins, or safety restrictions are substantive and remain reviewable. No tranche
authorizes live probes, key generation or
rotation, model-card signing, editing generated or append-only records outside a synthetic test harness,
pushing, or starting an additional M5 slice.
