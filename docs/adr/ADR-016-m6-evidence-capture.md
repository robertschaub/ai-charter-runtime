<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-016 — M6 full-pass evidence and dual-model capture

**Status:** definition reviewed at `582eaeb`, GO — no findings; implementation, live provider use, capture,
checkpoint push, and publication have not started and remain separately approval-gated. The separate M6.0a
anchoring prerequisite was reviewed at `be7f2ef`.
**Spec:** §§1, 3, 5, 6, 7, 9, and 10 (M6), especially the two-layer comparison rule in §7.
**Depends on:** ADR-001 through ADR-015 and the reviewed M5 baseline at `5251500`.

## Context

The bounded M5 milestone is complete, but the repository does not yet contain an M6 capture runner, public M6
artifact contract, live screening-model protocol, or native continuation from an authorization-owned verified
proposal through Commit to the mock services host. The reviewed screening path is deliberately fixture-backed,
and the browser path deliberately stops after Authorize → Submit → Verify. Reusing the legacy headless action route
for a live demonstration would weaken that boundary: the route accepts a complete caller-carried proposal and is
retained only as a synthetic HTTP-test seam.

The authoritative specification requires two different kinds of M6 evidence. First, every scripted beat and the
adversarial set must run deterministically under both acting-model lane configurations to show that gate semantics
do not depend on which model produced the evidence. Second, a live dual-model run of the core scenario must record
real proposals, provider-specific Submit projections, requested-versus-served identities, and containment. The
second layer exposes variance; it is not a controlled model-quality comparison or an independent evaluation.

At definition time, M6 had two unresolved prerequisites: ADR-003's remote check could not distinguish an honest
unpushed latest checkpoint from confirmed remote rollback, and the general `reverse` disposition was a known
unreachable-but-empty token. The first prerequisite was separately implemented and reviewed at `be7f2ef`; `reverse`
remains parked for M6.0b. This decision does not silently fold either correction into capture work.

## Decision

### 1. M6 produces bounded evidence, not a score or assurance result

M6 may establish only that the pinned POC implementation exercised its declared gates and produced the named
records under synthetic conditions. It must not rank the models; score model quality, empathy, safety, legality,
or legitimacy; claim semantic clearance; call the maintainer-run capture independent; or upgrade the partial and
not-assessed families already recorded in the M4 and M5 acceptance ledgers.

The public M6 ledger uses **exercised**, **partial**, **not assessed**, and **not applicable**. A command exit status
may be `pass` or `fail`; a governance surface or publication may not turn that into a green light, certification,
trust verdict, or deployment recommendation.

### 2. The comparison has an offline layer and a live observational layer

The **offline conformance layer** runs all twenty-two scripted beats and the complete named adversarial set twice:
once with each signed acting-model card selected as the initial lane. Provider calls use deterministic loopback
fixtures; model proposals and screening signals are pinned. Both runs use the same policy, synthetic case facts,
clocks, ids, expected outcomes, and declared provider permissions except where a beat is specifically testing a
provider projection or model identity. The resulting matrix binds every row to exact test ids and records any
legitimate lane-specific projection difference. This proves gate identity under fixed evidence, not model
equivalence or live detection quality.

The **live observational layer** runs the specification's core beats 0–6 and 19–21 through the native three-process
boundary with the two configured acting lanes and the mandate's separately authorized screening role. It records
acting and screening requests separately, including each projection and requested/served identity, along with the
lane order and immutable capture-plan digest.
The runs remain one append-only `w-demo` history; the runner must not reset or replace records to manufacture two
apparently independent samples. Because order and accumulated case state are not controlled away, the artifact is
explicitly unsuitable for causal or winner-versus-loser claims.

Beat 21's mismatch is forced only in the offline suite. A live provider must never be asked or configured to
substitute a model for the sake of the demo. The live layer records the served id actually returned; if it differs,
the existing quarantine and containment path governs. Absence of a live mismatch proves no prevention property.
No retry, fallback, silent endpoint switch, or second provider request is permitted after a definite or ambiguous
lane failure.

### 3. M6.1 replaces capture-time screening fixtures with authorization-owned live screening evidence

The deterministic fixture resolver remains the offline acceptance source, but it cannot be presented as live
detection. In live-capture mode, the fixed precommit coordinator pauses after Authorize `allow` and before each
screening-dependent Submit or Verify ruling. Authorization alone derives the eligible suspect items from the exact
current frozen proposal, gate, policy selector, mandate, four-store provenance, and screening-role permissions. It
selects the one exact current screening-role card from the mandate and creates a durable, boot-bound screening call
before returning the data-minimized projection and fixed request contract to the orchestrator.

The browser supplies no screening mode, gate, item, provider, prompt, schema, call, signal, or retry field. Live
versus fixture mode is fixed at listener startup and bound into the capture plan; live mode cannot fall back to a
fixture. Provider keys remain only in the orchestrator child. The orchestrator sends the exact authorization-owned
projection through the reviewed adapter once, with the fixed instruction and response schema, and returns the raw
response directly to authorization admission. It cannot submit a caller-constructed signal object.

Authorization admission requires the exact open call; verifies the served-model identity; strictly parses the
closed signal schema; rejects duplicate keys, unknown signal kinds, references outside the projection, and malformed
confidence/rationale fields; and persists only normalized signals, the output digest, model identities,
projection/card bindings, and fixed disclosure/outcome metadata. Raw screening output and provider errors are never
written to the WAL, records, logs, browser, or capture artifact. A mismatch, timeout, malformed or ambiguous
response, unavailable projection, invalidated currentness binding, or lost provider outcome records a fixed
failure/indeterminate state. Required screening then fails closed; no retry or provider fallback occurs.

After terminal admission or failure, the orchestrator repeats the same strict-empty precommit operation.
Authorization resumes only the next durable stage, revalidates the screening evidence inside the world lock, and
either issues that gate's ruling or pauses for the next screening call. The caller never chooses the gate. An exact
retry returns the same call or terminal evidence. Concurrent advances cannot create two calls for one
`{proposal_hash, gate, screening_role, policy_version}` binding.

Signals remain evidence only. They may raise an otherwise-allow result to Stop + escalate, preserve or narrow an
existing escalation, or leave a deny unchanged; they have no path to allow and never choose an intervention
contract or disposition. The live artifact labels their rationale as model-generated, not authorization fact.

The provider response schema is a strict array of at most sixteen objects containing only `signal`, nullable
`suspect_item_id`, `confidence_pct`, and a maximum-1,024-character `rationale`; duplicate
`{signal, suspect_item_id}` pairs are invalid. Authorization supplies `kind`, `model_id`, and
`model_version_reported` from the exact call and served-model evidence when constructing the stored
`ScreeningSignal`; model content cannot assert those fields.

M6.1 adds two Origin-guarded, access-recorded, non-authorizing `proc:orchestrator` terminal routes—screening-output
admission and screening-call failure—and extends the existing fixed precommit POST/status projections with a
content-bearing process-only `screening_required` branch and a redacted browser stage. The existing precommit POST
remains the only authority-changing route in that group and still owns gate order. The orchestrator gate/data
inventory rises from twenty-one to twenty-three:

| Authorization route | Caller and strict input | Result |
|---|---|---|
| `POST /w/{world_id}/screening-calls/{screening_call_id}/outputs` | `proc:orchestrator`; `{content, served_id}` only; content at most 64 KiB | authorization-derived admitted/withheld terminal evidence; never raw content |
| `POST /w/{world_id}/screening-calls/{screening_call_id}/failures` | `proc:orchestrator`; the existing closed model-call failure class, nullable served id, and no free-form error | authorization-derived failed/indeterminate terminal evidence |

The process-only precommit branch contains exactly the call id, proposal/run and gate binding, requested screening
card/model, expiry, 512-token/no-tools request ceiling, fixed response-schema id/digest, and bounded projection. The
browser branch contains only run id, lifecycle state, current gate, and prior ruling projections. The served id is
provider-supplied evidence and grants nothing. ADR-002 must carry these exact route/ACL classifications before code;
implementation schemas may only narrow the fixed fields and limits.

### 4. M6.2 adds one native, proposal-bound continuation to the mock effect

The live core cannot honestly claim beats 3 and 6 while the native proposal path stops before Commit. M6.2 therefore
adds a narrowly scoped execution-preparation protocol. It is not a general action API and does not reopen the
legacy headless route.

An active dynamic case-officer session may request one preparation for one exact proposal run whose current durable
precommit state ended with Verify `allow`. The browser mutation is a strict empty body on the run resource. The
orchestrator sends only the server-derived session claim and run id to authorization. Authorization resolves and
binds, from current state, the case, session, proposal id/hash/action/revision, conversation version, selection,
requested model and card, mandate, policy, system-use decision, final precommit rulings, service, action class, and
exact effect intent. None is accepted from the browser or model.

The preparation is boot-bound, maximum two minutes, single-use, and durable with
`issued → consuming → consumed | expired | invalidated`. An exact retry before use returns the same preparation;
ambiguous use never creates a second one. Session close, proposal succession, conversation or selection change,
mandate/card/policy/system-use invalidation, expiry, or a non-allow precommit state invalidates or refuses it.
Creating a preparation issues no ruling, reservation, nonce, commitment token, service call, or effect and is
classified non-authorizing.

Use is a second, explicit browser gesture carrying only the opaque preparation id over the same dynamic session.
The orchestrator may pass that id to the services host but receives no proposal, intent, ruling internals, nonce,
reservation, or commit token. The services host is the only caller allowed to consume the preparation at
authorization. Under the authorization world lock, consumption re-resolves every binding, runs Commit, and performs
the existing `commit-verify` transition for the exact stored intent. A deny or escalation returns no token and no
effect path. On allow, authorization returns the single-use, short-TTL commit token and exact intent only to the
services host. The host independently checks that token against the intent, writes the local mock effect and
idempotency outcome atomically, and reports the outcome through the existing authenticated channel.

The executing service, not authorization or the orchestrator, remains the terminal enforcement point. A user
gesture cannot create missing authority; it can only ask the gate to decide. The acting model remains proposal
evidence and has no code path to the preparation, Commit verdict, token, or effect.

M6.2 freezes these routes:

| Service | Route | Caller and strict input | Authority classification |
|---|---|---|---|
| Orchestrator/browser | `POST /w/{world_id}/cases/{case_id}/proposal-runs/{proposal_run_id}/execution-preparations` | exact dynamic case session; empty body | non-authorizing preparation |
| Authorization/process | same path at the authorization origin | `proc:orchestrator`; empty body plus server-derived on-behalf session headers | `authorityChanging: false`; Origin-guarded and access-recorded |
| Orchestrator/browser | `POST /w/{world_id}/cases/{case_id}/proposal-runs/{proposal_run_id}/execute` | same exact session; `{execution_preparation_id}` only | non-authorizing request to the services host |
| Services host | `POST /w/{world_id}/execution-preparations/{execution_preparation_id}/execute` | `proc:orchestrator`; empty body | carries no authority facts; service asks authorization to decide |
| Authorization/Commit | `POST /w/{world_id}/execution-preparations/{execution_preparation_id}/commit-verify` | `proc:services_host`; `{services_host_boot_id, services_ledger_id}` only | authority-changing Commit plus existing verification |

The existing proposal-run GET carries preparation/execution recovery to the process and a stricter redacted branch
to the browser; no additional status route is added. The one new authorization preparation route raises ADR-002's
post-M6.1 orchestrator gate/data inventory from twenty-three to twenty-four. Fixed precommit remains the only
authority-changing route available to `proc:orchestrator`; the new Commit boundary is denied to it. Existing browser
sessions remain denied on the headless `/actions/execute` seam, and M6 capture may not use that seam.

### 5. Every capture begins from an immutable plan

M6.3 introduces a versioned, strict capture-plan schema and a local runner. Before any provider call, the plan binds:

- capture id, scenario and beat set, lane order, fixed synthetic inputs, fixture digests, and expected stop/effect
  boundaries;
- runtime implementation commit, Charter commit, both authoritative source paths and digests, policy version and
  content digest, evaluator build id, signed-card ids/versions/digests, and the current system-use reference;
- public non-secret runtime configuration, Node/npm/OS versions, run start/end checkpoint requirements, artifact
  schema version, and intended screenshot/clip storyboard; and
- each command the runner may execute, its network classification, expected record roots, fixed provider-request
  ceilings, timeout policy, and the rule that no automatic retry or fallback exists.

The plan digest is ADR-007 canonical JSON under an `m6-capture-plan` domain. After preflight, no field may change.
A correction or rerun receives a new capture id and plan digest and links the superseded attempt; failed and
indeterminate attempts are retained in the public summary rather than overwritten by a later success.

The live lifecycle is `planned → preflighted → running → complete | failed | indeterminate → sanitized →
reviewed-for-publication`. Only the first three transitions can precede a provider request. Terminal states never
return to `running`.

The system-use record's `before-each-live-capture` cadence is stored and visible but is not currently backed by a
machine-enforced review event. M6 must not claim otherwise. Immediately before a live run, the runner displays the
principal-only bounded decision projection, verifies its currentness and hard conditions through authorization,
and records a plan-digest-bound operator attestation as `self_declared` procedural evidence. The attestation grants
no mandate, ruling, token, or action authority. Existing authorization-owned currentness and hard-condition checks
remain the machine controls at every model-call, ruling, commitment, and record boundary.

### 6. Public artifacts are fixed projections, never copied runtime records

M6.3 creates a machine-checked public schema under `docs/m6/` and a gitignored local staging area. Capture code may
read only purpose-built bounded projections and verifier results. It must not copy WAL, action, access, effect-ledger,
quarantine, provider transport, environment, or local agent files into the public artifact. `records/` remains
gitignored and is never hand-edited.

At minimum the public artifact set contains:

- `docs/m6/acceptance.md`, mapping every beat, adversarial case, baseline criterion, and test family to exact
  executable evidence and its honest coverage status;
- one immutable directory `docs/m6/captures/<capture_id>/` containing a strict manifest, the two-lane offline
  matrix, the bounded live-run projections, a failure/indeterminacy table, and asset digests; and
- screenshots and short clips for three storyboards: correction/escalation before reliance; successful narrowed
  continuation through a local mock filing; and governed model switching plus the offline mismatch-containment
  evidence. Live and fixture-derived frames are labelled so they cannot be confused.

The manifest binds the plan digest; implementation and checkpoint SHAs; the Charter provenance; policy/evaluator,
card, system-use, fixture, proposal, projection, requested/served-model, ruling, intervention, commitment, effect,
receipt, and artifact digests; command outcomes and timestamps; and explicit coverage limitations. A provider-served
id is labelled provider-supplied evidence. The publication commit SHA is recorded in the implementation ledger
after commit rather than embedded circularly in its own manifest.

Captured proposal and conversation text may be published only when it derives solely from the checked synthetic
scenario and has passed the fixed projection plus human privacy review. The public schema structurally excludes
credentials, tokens, key ids beyond already public verification identifiers, environment values, raw HTTP,
provider error bodies, endpoint secrets, local paths, private prompts, quarantine bytes, hidden governance
bindings, full evidence packs, and personal data. Screenshots must omit token-entry moments and browser/storage or
developer-tool views. The runner never prints secrets and never persists a raw provider response as a capture log.

Committed capture directories are immutable. A correction is a new directory and manifest linked by
`supersedes_capture_id`; it never rewrites the old artifact.

### 7. Preflight and live execution are separate approval boundaries

Offline M6 implementation and tests may use deterministic fixtures only. The implementation definition and every
authority-bearing source tranche receive exact-SHA adversarial review before any live run.

A live run additionally requires all of the following:

1. a clean, reviewed implementation commit already published on `origin/main`;
2. `npm run typecheck`, `npm test`, and `npm run cards:verify` passing at that commit;
3. both Charter digests re-verified read-only, signed cards unchanged and current, current system-use decision and
   hard conditions checked, the exact capture plan frozen, and no redecision trigger observed;
4. separate reviewed closure of the ADR-003 failed-push/rollback distinction and the known `reverse` disposition;
5. explicit action-time maintainer approval naming the capture id, plan digest, both acting lanes, the screening
   role/provider, and the separate bounded request ceiling for each; and
6. separate explicit approval for the run-start and run-end checkpoint commits and pushes required by ADR-003.

If any preflight item fails, the live run does not start. A stale card or changed provider configuration stops for a
separate model-card/provenance decision; M6 does not authorize probing, key work, or signing to repair it.

Live execution uses `runtime:start` and the real three OS processes. It does not call `tooling/probe.mjs`, bypass
authorization with an adapter, or contact a provider from a test-only seam. Listener-last startup and every existing
fail-closed boundary remain required. Only synthetic data and the local mock services are permitted; no real filing,
notification, payment, account change, or other external effect may occur.

### 8. Anchoring and publication remain explicit, reviewable operations

M6 exercises the real ADR-003 run-start and run-end checkpoint flow. The deferred implementation finding was
resolved in its own bounded definition and exact-SHA review at `be7f2ef`, so an honest failed push remains an
explicitly extended unanchored window while a confirmed rollback still halts. ADR-016 did not itself authorize or
silently include that correction.
A failed push remains evidence rather than a hidden success: it does not retroactively invent an anchor or erase a
completed synthetic run, but that capture cannot close M6 as remotely anchored. Any later attempt uses a new capture
id and fresh approval; M6 completion requires one reviewed capture with remotely acknowledged start and end anchors.

Checkpoint commits contain only the named append-only checkpoint paths. Capture artifacts are committed separately
after sanitization and exact-diff review. No capture command auto-stages, auto-commits, or auto-pushes public
artifacts. A live-run approval is not publication approval, and publication approval is not permission to rewrite
or sign a model card.

The final README/spec review is cross-model and exact-SHA. The reviewer reads the pinned specification from the
immutable Charter commit, treated read-only; this repository never copies or edits it. Any required specification
change is proposed and published upstream under separate approval, after which this repository moves both
provenance rows together in a separately reviewed commit. Maintainer-run results remain a method dry-run even when
two model families review the text.

### 9. M6 is implemented and reviewed in bounded slices

Definition review authorizes no code. Subject to separate maintainer approval after a GO disposition, the sequence
is:

1. **M6.0 prerequisites:** separately define, correct, test, and review the ADR-003 failed-push distinction and the
   unsupported `reverse` disposition. Neither change is included in this definition commit.
2. **M6.1 authorization-owned live screening protocol:** implement §3 and its paused fixed-precommit state machine
   with synthetic loopback providers only. Prove projection minimization, exact call/evidence binding, signal
   monotonicity, fail-closed terminal states, no retry/fallback, ACLs, and raw-byte exclusion. Stop for exact-SHA
   review; no live provider call is authorized.
3. **M6.2 native commitment continuation:** implement §4 with synthetic loopback tests only. Prove exact binding,
   ACLs, denial/escalation, races, invalidation, ambiguous failure, idempotent recovery, and no headless/browser
   bypass. Stop for exact-SHA review.
4. **M6.3 offline full pass and capture contract:** add the strict plan/artifact schemas, deterministic two-lane
   twenty-two-beat and adversarial matrix, acceptance ledger, local staging boundary, sanitization checks, and
   dry-run assets. No live provider. Stop for exact-SHA review.
5. **M6.4 approved live capture and publication:** freeze and review one plan, obtain action-time provider and push
   approvals, perform the bounded live run, sanitize without rewriting evidence, review the resulting artifact,
   then obtain separate commit/push approval. Only after the published exact SHA and final cross-model review may a
   documentation-only closure mark M6 complete.

## Acceptance tests for the implementation slices

- Every scripted beat and adversarial case has an exact test id and runs under both initial lane configurations;
  missing, skipped, duplicate, or unmapped rows fail the M6.3 matrix.
- The paused live-screening protocol proves Authorize precedes disclosure; authorization derives the projection,
  card, role, gate, call, and schema; exact terminal evidence resumes only the next gate; and every signal remains
  unable to allow. Missing, malformed, mismatched, stale, duplicate, concurrent, or ambiguous results fail closed
  without retry, fallback, raw persistence, or caller-asserted evidence.
- The native successful path proves model evidence → authorization-owned frozen proposal → fixed precommit → one
  execution preparation → fresh Commit decision → services-host `commit-verify`/token check → one local mock effect
  → outcome and receipt, with exact ids/hashes joined across the record.
- Deny, escalation, expired/stale preparation, wrong session/case/run, proposal succession, model switch, mandate,
  policy, card, system-use, process boot, duplicate use, concurrent use, lost response, and services restart all fail
  closed or recover to the one existing outcome without duplicate authority or effect.
- Real-listener ACL tests prove the dynamic browser cannot reach headless execution, `proc:orchestrator` cannot
  consume/Commit an execution preparation, and the services host cannot create or alter a preparation. Strict bodies
  refuse caller-carried proposal, gate, service, action, parameters, authority, retry, ruling, or token fields.
- Capture schema tests reject unknown keys, absent provenance, unhashed assets, secret-shaped fields, raw record or
  transport content, local paths, mutable capture replacement, unlabelled live/fixture evidence, and success-only
  summaries that omit failed or indeterminate attempts.
- The live runner's dry-run proves zero network requests, zero checkpoint pushes, zero git staging, and zero writes
  outside the gitignored staging root. Network mode requires the exact reviewed plan digest and explicit bounded
  approval evidence; tests cannot synthesize that into a real provider call.
- `npm run typecheck`, `npm test`, `npm run cards:verify`, `npm run verify:records -- --local`, and
  `git diff --check` pass at each implementation review point. The live run additionally exercises remotely
  acknowledged start/end anchors after the separate correction and push approval.

## Deferred and excluded

M6 does not add real data, real external effects, general action execution, automatic retries or provider fallback,
semantic empathy or safety scoring, production identity, independent custody, a remedy decider, post-commit
compensation, retention/deletion propagation, M7 article claims, or an evaluation of either provider. The M5
partial/not-assessed boundaries stay visible.

This definition does not authorize live probes or provider calls, key generation or rotation, card signing,
generated/append-only record edits, upstream Charter edits, commits of captured material, or pushes.

## Consequences

M6 gains a path that can demonstrate the full architectural invariant on a live model proposal: the model proposes,
authorization decides from stored current state, and the executing mock service verifies again before one local
effect. The cost is a new protocol surface that must be reviewed before capture and may not be replaced by the more
convenient legacy headless seam.

The two-layer evidence design also keeps the model comparison honest. Deterministic paired fixtures can establish
gate identity; live runs can expose only what those two provider calls actually returned under a recorded order and
configuration. Neither can establish general model quality or independent assurance.
