<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# ADR-020 — M6.4 live capture and publication

**Status:** definition candidate; review pending. This document authorizes no implementation, provider call,
system-use renewal, checkpoint operation, capture, commit, push, or publication.
**Spec:** runtime specification §§6, 7, 9, and 10 (M6), especially the two-layer comparison rule and beats 0–6
and 19–21.
**Depends on:** ADR-003, ADR-008, ADR-016, ADR-018, ADR-019, and the reviewed maintenance baseline at `20fe6e9`.

## Context

M6.3 supplies a closed offline catalog, strict v1 plan and artifact schemas, deterministic execution, sanitization,
and gitignored staging. It deliberately has no live-provider path. M6.4 must add the live observational layer
without weakening that boundary or presenting provider variance as gate, model, safety, or quality assurance.

The checked-in synthetic system-use decision expired on 2026-09-30. Runtime currentness correctly fails closed,
and the current-clock test helper is deliberately unavailable to production code. The supported supervisor does
not yet pass a system-use successor or live-screening selection into authorization, and the v1 M6 manifest cannot
represent a live attempt. These are prerequisites to define and review, not reasons to bypass currentness.

The repository also has a known historical non-fast-forward publication predating this definition. Current branch
protection has been read back with force-pushes and deletion disabled and admin enforcement enabled, but the event
and its authorization still require continuity recording before a live plan may rely on the remote as the
force-push-protected acknowledgement surface assumed by ADR-003.

## Decision

### 1. Definition and implementation remain separate gates

This ADR freezes M6.4's architecture and acceptance boundary only. A reviewed definition may be followed by a
separately approved implementation using synthetic loopback providers and injected remote observations. No live
provider request, checkpoint commit or push, public capture, or publication occurs during definition or
implementation review.

After implementation receives exact-SHA GO, one concrete live plan, one system-use successor, the action-time
provider budget, and the checkpoint operations each remain separately approval-gated. A live-run approval is not
publication approval.

### 2. The expired decision is replaced by an exact reviewed successor, never edited or silently renewed

The M6.4 decision is a new version of `sud_public_grant` that names version 1 in `trace.supersedes`. Version 1 and
its digest remain unchanged. The successor retains the same world, use case, system id, material configuration,
policy, signed-card set, hard conditions, and synthetic-only boundary unless a separately reviewed specification
and mandate change says otherwise. Its refreshed evidence references, validity interval, review cadence,
redecision triggers, limitations, accountability fields, and digest are reviewed as one exact document.

The live plan binds all of the following:

- predecessor decision id, version, record digest, source path, and source digest;
- successor decision id, version, record digest, source path, and source digest;
- the exact current material-configuration digest, policy version, card bindings, hard-condition results, and
  validity interval; and
- the maintainer's action-time approval of the exact successor digest and plan digest, recorded as
  `self_declared` procedural evidence rather than an independent assurance claim.

The successor is installed only through an authorization-process startup seam. After read-only record
verification, authorization verifies or installs the unchanged v1 fixture, then atomically replaces it with the
exact successor before case recovery, services health probing, or listener binding completes. Restart is
idempotent: an exact already-installed successor with an already-superseded predecessor produces no operation; an
absent successor is installed through the existing invalidating replacement transaction; any altered predecessor,
altered successor, unexpected version, partial state, ambiguity, or invalid digest halts startup. No browser,
HTTP, orchestrator, provider, or services-host route can create, replace, transition, or select a system-use
decision.

Implementation may add `RUNTIME_SYSTEM_USE_SUCCESSOR` and `RUNTIME_SCREENING_MODE=live` to the supervisor's
authorization-child allow-list. The successor path and both file digests are fixed by the plan and contain no
secret. Neither variable may reach the orchestrator or services host, and the test-only
`gate-core/test-support` subpath is forbidden from all production modules and live commands.

The actual successor document is not part of this definition. Preparing or committing it is a later principal
governance act requiring explicit approval and exact-content review.

### 3. M6.4 has a separate live entry point; M6.3 remains offline-only

Implementation adds a separate `m6:live` entry point, owned by a new `packages/m6-live` package. It may share the
versioned schema registry and bounded projection types, but it does not add a `live` flag to the M6.3 CLI, widen
M6.3's import allow-list, or make an offline command network-capable.

The exact interface is `npm run m6:live -- --plan <relative-path>`. The normalized path must resolve to the exact
`.m6-staging/<capture_id>/plan.json` bound by the plan itself. It rejects endpoint, model, prompt, credential,
retry, fallback, checkpoint, push, publication, effect-target, and write-root overrides. Provider endpoints and
requested model ids come from the reviewed card/runtime configuration bound by the plan; credentials remain in
`.env.local`, are partitioned by the existing supervisor, and never enter arguments, output, artifacts, records,
or logs.

The live coordinator does not load `.env.local` and receives no role credential, HMAC key, provider key, case
session, or authority-bearing token. It starts the exact `runtime:start` child command with a scrubbed environment
containing only system variables and plan-bound non-secret Runtime settings; that child alone loads `.env.local`
and partitions credentials through the existing supervisor. The coordinator may consume only fixed safe process
lifecycle events. It never captures or persists arbitrary child stdout/stderr.

The operator performs the fixed synthetic beats through the existing governance and case consoles. Tokens are
entered only into their current local surfaces and are omitted from every screenshot. The live coordinator does
not impersonate a principal, case officer, applicant, orchestrator, authorization process, or services host.
After clean shutdown, a non-authorizing projection pass verifies the record chains and derives the bounded capture
fields; it cannot issue a mandate, ruling, decision, preparation, token, or effect.

The entry point composes the existing listener-last three-process supervisor and the native dynamic-session path.
It may not use the legacy headless `/actions/execute` seam, call an adapter directly, invoke `tooling/probe.mjs`,
or contact an external effect target. The only effect remains the local mock filing after the services host
performs the reviewed M6.2 Commit and token verification.

Live versus fixture screening is fixed before authorization starts and bound by the plan. Live mode has no fixture
fallback. The runner cannot choose a gate, signal, proposal binding, intervention contract, ruling, token, or
effect. Authorization and the services host retain those decisions exactly as reviewed.

### 4. A v2 plan binds the live environment and exact network budget

M6.4 adds `m6-capture-plan/v2`; v1 remains valid only for M6.3 offline and dry-run artifacts. The v2 plan carries
all v1 bindings and adds or narrows:

- current Runtime specification and system-use companion paths and digests in this repository, plus the immutable
  historical Charter provenance commit, paths, and digests recorded in the implementation plan;
- Runtime source commit, `package-lock.json` digest, top-level/workspace package-manifest set digest, evaluator
  build id/digest, policy version/digest, catalog digest, fixture-set digest, and all artifact-schema versions;
- the predecessor/successor system-use bindings from §2;
- exact non-secret provider origins, requested model ids, signed-card ids/versions/digests, lane order, and the
  separately authorized screening role;
- separate maximum request counts for acting lane 0, acting lane 1, and screening, plus a zero-external-effect
  rule and the exact local-mock-effect ceiling;
- `network_classification: live`, the one `m6:live` command, the exact phase-bound checkpoint write/commit/push/
  observe command templates, timeout, no-retry/no-fallback rules, and the single `.m6-staging` write root; and
- mandatory `remotely_acknowledged` run-start and run-end checkpoints, repository/branch binding, and the exact
  public artifact/storyboard inventory.

The plan derives request ceilings from a closed step graph before approval; a caller cannot increase them at run
time. Every attempted provider disclosure consumes the applicable ceiling, including timeout, malformed output,
served-id mismatch, or ambiguous transport outcome. Reaching a ceiling halts that lane. No failed or ambiguous
request is retried and no provider or model fallback exists.

After `preflighted`, the plan is immutable. Any correction, configuration drift, successor change, card change,
dependency change, branch/repository change, or larger budget requires a new capture id, plan digest, review, and
approval.

### 5. Preflight must close before the first provider disclosure

The v2 live state machine is
`planned → authority-prepared → preflighted → running → complete | failed | indeterminate → sanitized →
reviewed-for-publication`. M6.3's v1 states remain unchanged. Only `preflighted → running` can precede a provider
request.

The first invocation is an authority-preparation boot. With explicit approval of the exact plan and successor, it
starts the three processes without making a provider request, installs or verifies the successor, closes the
processes cleanly, records `authority-prepared`, and stops with `run-start-anchor-required`. The successor WAL
entry and preparation boot records therefore exist before the start checkpoint is written. An exact reinvocation
before remote acknowledgement remains in `authority-prepared` and cannot contact a provider.

The separately approved checkpoint interface is
`npm run m6:checkpoint -- --plan <relative-path> --phase <run-start|run-end> --operation <write|commit|push|observe>`.
It has distinct write, commit, push, and observe operations for each phase.
The write operation calls the existing append-only checkpoint writer. The commit operation stages and commits
only the exact new checkpoint chain paths and `docs/checkpoints/latest.json` using explicit pathspecs. The push
operation uses no force, pull, fetch-and-reset, rebase, branch move, or credential prompt. None of those operations
chains automatically to the next, and each requires its own explicit approval. Observation is read-only and
records `anchor` only after current remote containment succeeds; failure records the bounded `anchor_failed`
class. The live command cannot invoke any of these Git operations.

After the run-start checkpoint is remotely acknowledged, the same plan starts a fresh live boot. Authorization
re-verifies the exact installed successor and the current remote checkpoint before the orchestrator becomes ready.
Preflight then fails closed unless all of the following are true at the same candidate state:

1. the working tree is clean; the plan's reviewed Runtime source commit is an ancestor of the exact remotely
   acknowledged run-start checkpoint commit; every intervening commit changes only the named append-only
   checkpoint paths; and the source/dependency digests still match the plan;
2. typecheck, the full test suite, M6 schemas, and signed-card verification passed at that commit;
3. current specification, companion, provenance, policy, evaluator, dependency, card, catalog, fixture, and
   system-use digests exactly match the plan;
4. the successor is current, uniquely applicable, hard conditions are satisfied, no redecision trigger is
   observed, and authorization's principal-only projection matches the plan;
5. branch-protection posture was checked read-only and its single-custodian limitation and the historical
   non-fast-forward event are recorded; this is procedural evidence, not an independent control;
6. ADR-003 verification returns a current `remotely_acknowledged` run-start checkpoint bound to the exact
   repository and branch; and
7. the earlier successor-installation approval is recorded against the exact capture, plan, and successor digests;
   and
8. a distinct action-time provider approval names the capture id, plan digest, both acting lanes, screening
   role/provider, and each request ceiling.

The operator's plan-bound `before-each-live-capture` attestation remains `self_declared` and non-authorizing.
Runtime currentness and hard-condition enforcement—not the attestation—control case creation, model calls,
rulings, commitment, and records.

Preflight performs no provider request. Remote unavailability, ambiguous acknowledgement, an unanchored start,
stale authority, or an unknown check halts without falling back to local-only verification.

### 6. The live layer is observational and bounded to core beats

The runner executes core beats 0–6 and 19–21 through the native three-process path with the two configured acting
lanes and the one authorized screening role. It records the fixed synthetic prompts and inputs, plan/lane order,
authorization-owned provider projections, request/response digests, requested and provider-served model ids,
normalized screening evidence, frozen proposal hashes, rulings, interventions, commitment/effect state, receipts,
and terminal failure classes through bounded projections only.

Live behavior is not forced to match the offline expected proposal. A model that omits, varies, refuses, or
malforms a requested step produces the corresponding failed or indeterminate observation; it is not reprompted to
manufacture a successful story. Beat 21 is never induced live. If a provider independently reports a foreign
served id, the existing quarantine/containment path governs and the lane halts.

The two lanes run in the frozen order in one append-only `w-demo` history. Records are not reset, copied, edited,
or relabelled to create independent samples. The artifact may compare gate containment and provider projections;
it may not rank models, infer causal provider differences, or claim semantic quality, safety, equivalence, or
production readiness.

### 7. Run-end acknowledgement is mandatory for a completion claim

After the last terminal live observation, the processes close cleanly before the separately approved checkpoint
tool writes the run-end checkpoint through the existing writer. Its write, commit, push, and observation steps
remain distinct from one another and from the provider-run approval. A read-only current remote observation must
then prove containment of the exact checkpoint commit.

The bounded public checkpoint projection contains exactly `checkpoint_id`, `composite_digest`,
`checkpoint_commit_sha`, `remote_head_sha`, `repo_url`, `branch`, and `observed_at`. Stored historical anchor
events, `--local`, an availability warning, a local commit alone, or a prior remote observation cannot satisfy the
predicate.

If the run-end push or observation fails, the provider attempt remains append-only evidence but the capture is
`failed` or `indeterminate` and cannot close M6. No automatic pull, rebase, retry, force operation, branch move, or
recovery run occurs. A later attempt requires a new capture id, plan, approval, and request budget.

### 8. Live artifacts use closed v2 schemas and bounded projections only

M6.4 adds, without widening the v1 offline schemas:

- `m6-capture-plan/v2`;
- `m6-live-observations/v1`, containing only the bounded fields named in §6;
- `m6-checkpoint-observations/v1`, containing the two seven-field acknowledgement projections;
- `m6-attempt-events/v2`, adding `authority-prepared` and the live layer without making terminal attempts
  restartable;
- `m6-sanitization-report/v2`, covering every v2 artifact and media asset; and
- `m6-capture-manifest/v2`, binding the live projections, start/end acknowledgement, plan, offline matrix,
  limitations, media digests, and `publication_state: staged-not-published`.

Capture code reads purpose-built projections and verifier results only. It never copies WAL, action/access chains,
effect-ledger files, quarantine, raw provider bytes, HTTP traffic, environment variables, `.env.local`, keys,
tokens, local paths, private prompts, browser storage, developer-tool views, or private continuity records.
Provider errors are represented only by the existing closed failure class. Raw acting and screening responses are
not capture logs.

Every artifact is canonical JSON written exclusively under `.m6-staging/<capture_id>/`. Unknown files, symlinks,
hard links, path escapes, duplicate/case-colliding ids, schema drift, digest mismatch, or an unlisted asset fails
closed. A failed or indeterminate attempt is retained in the manifest rather than overwritten by a later result.

### 9. Sanitization, human review, materialization, and publication are distinct steps

Machine sanitization checks closed schemas, exact inventory, digests, forbidden keys/patterns, and asset metadata.
It cannot claim semantic privacy review. A human review must confirm synthetic-only content, labels, limitations,
screenshots/clips, absence of secrets and personal data, and consistency with the exact runtime evidence before the
attempt may become `reviewed-for-publication`.

Only the separately approved
`npm run m6:materialize -- --plan <relative-path>` command may copy the reviewed staging projection into a new
immutable `docs/m6/captures/<capture_id>/` directory. It refuses an existing destination and never stages,
commits, or pushes. An exact public diff is then reviewed. Commit and push each require explicit approval; the capture
manifest cannot embed its own publication commit circularly. After publication, the implementation plan records
the public SHA and final cross-model review. Corrections use a new capture id and `supersedes_capture_id`; committed
capture artifacts are never edited or deleted.

M6 closes only after one public capture has both remotely acknowledged boundaries, reviewed live and offline
projections, honest failure/coverage labels, and a published exact SHA. This remains a maintainer-run method
demonstration, not independent evaluation, assurance, certification, or deployment approval.

## Implementation slices after definition GO

1. **M6.4a — schemas and preflight:** v2 schemas, plan validation, dependency/source binding, closed command and
   import boundaries, remote-acknowledgement projections, and deterministic no-network tests.
2. **M6.4b — successor and live entry point:** authorization-only restart-idempotent successor installation,
   supervisor partitioning, separate live package, native-path coordinator, ceilings, failure handling, and
   synthetic loopback integration tests only.
3. **M6.4c — staging and publication mechanics:** bounded projections, sanitization, media inventory,
   review/materialization transitions, immutable destination handling, and deterministic tests only.
4. **Live preparation:** after exact-SHA GO for all implementation slices, prepare and review one successor and one
   frozen plan. This step still makes no provider call or checkpoint push.
5. **Approved execution and publication:** obtain the separately named approvals at each boundary in §§5, 7, and
   9. No earlier approval carries forward implicitly.

## Acceptance tests for implementation

Implementation is not acceptable unless deterministic tests prove:

1. v1 offline commands remain network-incapable and reject live plans;
2. v2 schemas reject unknown fields, unbound dependencies, loose budgets, missing artifacts, and invalid state
   transitions;
3. only authorization can install the exact successor; fresh, restarted, partial, altered, stale, ambiguous, or
   out-of-order histories behave as §2 requires, and the listener binds last;
4. no production file imports `gate-core/test-support`, and the checked-in v1 fixture remains byte-identical;
5. no provider client can run before exact preflight and current run-start acknowledgement;
6. each attempted disclosure consumes the correct lane/screening ceiling and no failure path retries or falls
   back;
7. the runner reaches providers only through the real supervisor, orchestrator, authorization-owned screening and
   native session/precommit path; the headless seam and direct adapters are refused;
8. model output and screening signals cannot grant authority, choose a gate, or bypass current system-use,
   mandate, policy, card, session, Commit, or services-host checks;
9. beat 21 is never forced live, a spontaneous served-id mismatch quarantines output, and no raw bytes enter
   records or artifacts;
10. missing, unavailable, ambiguous, rolled-back, local-only, stale, or mis-bound start/end checkpoint evidence
    prevents the corresponding run/publication transition;
11. capture output contains only the closed bounded projections and exact inventory, and synthetic secret/path/raw
    payload canaries are refused;
12. failed and indeterminate attempts remain terminal and retained; a new attempt cannot reuse their capture id or
    budget;
13. sanitization cannot confer `reviewed-for-publication`, materialization cannot overwrite, and no live,
    capture, or materialization command stages, commits, pushes, signs, or publishes; each checkpoint command
    performs only its one explicitly approved operation and never chains to another; and
14. all existing typecheck, Git-safety, Runtime, M6.3, schema, and signed-card verification baselines remain green.

## Honest limits

The live layer observes two provider-backed executions of a synthetic workflow. It does not establish model
quality, legal compliance, fairness, safety, system legitimacy, provider identity integrity, independent custody,
or deployment readiness. Provider-served ids remain provider claims. The operator remains rulemaker, operator,
record keeper, and reviewer; the plan-bound attestations are self-declared. External effects, real people and data,
semantic privacy detection, independent remedy, post-commit compensation, and live forced-substitution testing
remain outside this POC.
