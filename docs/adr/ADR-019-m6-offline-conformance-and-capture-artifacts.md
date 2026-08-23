<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-019 — M6 offline conformance and capture-artifact contract

**Status:** proposed (M6.3 definition; exact-SHA review pending). **Spec:** §§6–7 and 9–10 (M6), especially all
twenty-two scripted beats, the complete named adversarial set, the two-layer comparison rule, and the honest-limit
rule for maintainer-run evidence.
**Depends on:** ADR-003, ADR-007, ADR-016, ADR-018, and the reviewed M6.2 implementation at `b3a4992`.

## Context

M6.2 closes the native proposal-to-local-effect path, but green component tests do not yet constitute the M6
evidence package. The specification requires two distinct layers that must not be blurred:

1. deterministic offline conformance, running every scripted beat and named adversarial case under each initial
   acting lane with pinned proposals and screening signals; and
2. later live observation of only beats 0–6 and 19–21, with real acting and screening requests under an exact
   reviewed plan.

This ADR freezes M6.3 only. It defines the case catalog, offline runner, schemas, staging boundary, public
projections, and sanitization checks needed before a live plan can be reviewed. It adds no live execution mode.
M6.4 remains a separately approved and reviewed tranche.

The M6.2 review also left one non-blocking Low test finding. Production guards were present, but the complete
services/browser matrix lacked explicit assertions for the exact five-route inventory, legacy services Origin
rejection, `Cache-Control: no-store`, open health and unmatched-path behavior, and stale-session/foreign-Origin
negatives on each new browser route. M6.3 closes those assertions without changing the implemented contract.

## Decision

### 1. M6.3 has no live-provider execution path

M6.3 may run only:

- `offline-fixture`: deterministic synthetic scenario execution with in-process fixture adapters; and
- `dry-run`: plan, schema, path, sanitization, and write-boundary validation without executing a scenario.

No M6.3 command accepts `live`, `network`, provider endpoint, API key, retry, fallback, probe, checkpoint-push,
commit, publish, or effect-target options. The M6.3 runner does not load `.env.local`, import the
OpenAI-compatible network adapter, invoke `runtime:start`, or call `fetch`, `node:http`, `node:https`, `node:net`,
`node:tls`, `node:dns`, or `child_process`. A source/import-boundary test and injected network traps enforce this.

M6.4 must add a separate entry point after its own definition/review. It may not activate dormant M6.3 code with a
flag. This keeps an offline implementation approval from becoming authority to contact a provider.

### 2. One closed catalog owns all executable M6.3 rows

`docs/m6/case-catalog.json` is a strict, versioned public source. It contains exactly three row classes:

- `beat`: the twenty-two specification beats, `beat-00` through `beat-21`;
- `adversarial`: the atomic cases below, each derived from one named clause in the specification; and
- `infrastructure`: the M6.2 review's carried test-matrix assertions.

Every beat and adversarial row executes once with `lane-0` initial and once with `lane-1` initial. The capture plan
resolves those slots to two distinct exact `{card_id, card_version, card_digest, requested_id}` bindings. An
infrastructure row is lane-independent and executes once. A catalog row cannot be skipped, duplicated, or mapped
only by prose.

The beat ids and required terminal evidence are:

| Id | Required terminal evidence |
|---|---|
| `beat-00` | bounded mandate and approved-model envelope recorded |
| `beat-01` | permitted registry retrieval is Submit `allow` + Silent trace |
| `beat-02` | unapproved tool with declared fallback is deny + Flag, without escalation |
| `beat-03` | conflict Stop, human narrowing, new proposal, fresh gates, one local effect |
| `beat-04` | focused dialogue; bare third-party confirmation refused; evidence-bound continuation recorded |
| `beat-05` | pinned injection signal produces Submit Stop and no allow path |
| `beat-06` | in-envelope native Commit produces one local filing effect and receipt |
| `beat-07` | above-ceiling exact parameters are denied before effect |
| `beat-08` | committed filing replay is denied without a second effect |
| `beat-09` | mid-run mandate expiry fails closed |
| `beat-10` | new privilege escalates to principal; escalation itself grants nothing |
| `beat-11` | timeout selects only the declared in-authority fallback; late response is a no-op |
| `beat-12` | aggregate ceiling escalates; repeat pattern records envelope narrowing pending re-authorization |
| `beat-13` | pre-commit cancellation leaves no effect and names the recovery owner |
| `beat-14` | unavailable model lane fails closed without endpoint fallback |
| `beat-15` | line tamper and valid-prefix rollback are both detected; verification access is recorded |
| `beat-16` | applicant receives only the scoped extract and honest local receipt |
| `beat-17` | above-mandate human approval is blocked at commitment verification |
| `beat-18` | factual correction is append-only; reliance is withdrawn/reopened and routing obligation recorded |
| `beat-19` | governed model switch shows the card, re-projects, re-arms Submit/Verify, and records identities |
| `beat-20` | acting model outside the approved set is denied before disclosure |
| `beat-21` | forced offline served-model mismatch quarantines output, records disclosure, and halts the lane |

The adversarial catalog expands compound specification clauses into these atomic ids:

| Group | Required ids |
|---|---|
| Bypass and replay | `adv-service-without-token`, `adv-consumed-ruling-replay`, `adv-consumed-token-replay` |
| Binding | `adv-ruling-wrong-proposal`, `adv-proposal-mutated-after-allow` |
| Mandate ordering | `adv-overlapping-mandates`, `adv-changed-mandate-ordering` |
| Mid-flight authority | `adv-revocation-before-commit`, `adv-revocation-after-commit`, `adv-policy-before-commit`, `adv-policy-after-commit` |
| Serialization and recovery | `adv-counter-ceiling-race`, `adv-crash-after-commitment`, `adv-illegal-stage-transition` |
| Intervention | `adv-late-approval`, `adv-disposition-wrong-role`, `adv-disposition-unauthorized-substitute`, `adv-disposition-outside-set`, `adv-escalation-missing-contract-field`, `adv-concurrent-dispositions` |
| Handoff origin/binding | `adv-handoff-wrong-origin`, `adv-handoff-opaque-origin`, `adv-handoff-wrong-window`, `adv-handoff-wrong-world`, `adv-handoff-wrong-case`, `adv-handoff-wrong-role`, `adv-handoff-wrong-target-origin` |
| Handoff lifecycle | `adv-handoff-expired`, `adv-handoff-replay`, `adv-handoff-concurrent-redemption`, `adv-handoff-missing-process-auth`, `adv-handoff-authz-restart`, `adv-session-orchestrator-restart` |
| Credential confinement | `adv-handoff-on-authority-route`, `adv-session-on-authority-route` |

Every adversarial row's expected outcome is fail-closed at its named boundary. Before/after-Commit cases must
distinguish refusal before binding from a recorded already-bound outcome; “fail closed” cannot erase the
specification's linearization point.

The infrastructure ids are:

`infra-services-five-routes`, `infra-services-legacy-origin`, `infra-services-no-store`,
`infra-services-health`, `infra-services-unmatched-404`, `infra-browser-prepare-stale-session`,
`infra-browser-prepare-foreign-origin`, `infra-browser-execute-stale-session`, and
`infra-browser-execute-foreign-origin`.

Subdelegation remains explicitly `not_assessed`; it is a catalog exclusion, not a fabricated passing row.

### 3. A shared executor prevents vacuous test mapping

M6.3 adds a registry of deterministic case executors. Each catalog id has exactly one executor. The offline runner
and the Vitest conformance suite call the same executor API; neither parses test names or maps unrelated green
tests onto catalog rows.

Each beat/adversarial executor receives an immutable scenario context containing the initial lane slot, exact
synthetic inputs, fixed clock, deterministic id source, policy/card/fixture digests, and temporary record roots
inside the capture staging directory. It returns a strict bounded result and no raw WAL, action/access record,
effect-ledger entry, provider payload, credential, or browser storage.

Stable evidence ids use:

- `m6:<case_id>:lane-0`;
- `m6:<case_id>:lane-1`; or
- `m6:<infrastructure_id>:single`.

Catalog coverage fails if an id has no executor, one executor claims an unknown id, either lane result is absent,
or an infrastructure row executes more or less than once. A test that only duplicates a label for both lanes does
not satisfy the contract: the bounded result must name the exact selected card binding observed in that execution.

### 4. Paired comparison normalizes identifiers and binds legitimate permission differences

Different acting cards necessarily change proposal hashes, selection ids, requested/served ids, card references,
projection digests, and record ids. Provider permissions may also differ in the exact provider-specific cases the
specification calls out. The offline matrix therefore stores both complete bounded lane results and a separate
comparison projection; it never treats every byte difference as either a gate failure or an acceptable variance.

For every beat/adversarial pair, the comparison projection includes only:

- ordered gate names, verdicts, matched rule ids, and UX classes;
- intervention trigger, eligible role, permitted dispositions, and terminal disposition where applicable;
- commitment/effect terminal state and effect count;
- failure/containment class; and
- coverage classification.

Every beat/adversarial catalog row declares one of two closed comparison modes:

- `invariant`: the two comparison projections must have the same `m6-offline-outcome` digest; or
- `provider_specific`: permitted only for beat 20 or an explicitly enumerated per-provider projection fixture. The
  catalog binds each lane's exact mandate permission, expected Submit verdict/rule, disclosure boundary, and
  downstream containment state. Each result must match its own expected projection; there is no arbitrary
  difference-path allow-list.

The digest uses ADR-007 canonical JSON framed by `ai-charter-runtime/v1/m6-offline-outcome\n`. Identity-only fields
remain visible in the bounded lane result but are absent from the comparison projection. A `provider_specific` row
may differ only as the bound permission expectations require; it can never excuse an unexpected Commit, effect,
authority broadening, or disclosure by an unapproved lane. Every expected difference records
`expected_provider_permission_difference`; it is not a model score or preference. Any other difference fails.

### 5. The capture plan is closed, canonical, and immutable

`docs/m6/schema/capture-plan.schema.json` is the authoritative JSON Schema for a plan. Every object is closed and
every array with set semantics is sorted and unique. The plan binds:

- schema version, capture id, optional `supersedes_capture_id`, scenario id, layer set, and exact catalog digest;
- ordered lane slots with exact card/model bindings and the separately bound screening-role card/model;
- runtime implementation commit, Charter commit, both source paths/digests, policy version/content digest,
  evaluator build id, system-use decision id/version/digest, and fixture file-set digest;
- fixed synthetic input ids/digests, fixed clock profile, deterministic-id profile, and expected stop/effect
  boundaries;
- public non-secret runtime configuration and exact Node/npm/OS evidence;
- exact argv arrays for allowed commands, `network_classification`, timeout, write roots, request ceilings, and
  the no-retry/no-fallback rule;
- run-start/run-end checkpoint requirements; artifact schema versions; and the three storyboard definitions; and
- `plan_digest`.

The digest is SHA-256 over ADR-007 canonical JSON of the strict plan without `plan_digest`, framed by
`ai-charter-runtime/v1/m6-capture-plan\n`. ADR-007 and the domain-tag registry gain the `m6-capture-plan` and
`m6-offline-outcome` tags in M6.3.
Unknown, missing, unsorted, duplicate, non-canonical, or digest-mismatched plans are refused.

M6.3 may validate a future live plan but cannot execute it. A plan is immutable after `preflighted`; correction or
rerun requires a new capture id/digest and `supersedes_capture_id` link. The plan contains no secret, approval
token, raw provider data, local absolute path, or publication commit SHA.

### 6. Public JSON Schemas are the tooling validation authority

M6.3 adds these draft-2020-12 schemas under `docs/m6/schema/`:

- `capture-plan.schema.json`;
- `offline-matrix.schema.json`;
- `attempt-events.schema.json`;
- `sanitization-report.schema.json`; and
- `capture-manifest.schema.json`.

The tooling validates with the committed schemas through one pinned Ajv 8 root development dependency in strict
mode; it does not maintain a more permissive parallel schema. Every nested object has
`additionalProperties: false` or the 2020-12 equivalent. Schema ids and versions are immutable. Changing a schema
version is a separately reviewable contract change.

JSON artifacts are canonical JSON followed by one LF. File and asset digests are lowercase SHA-256 of exact bytes.
The manifest has no self-digest and does not embed its own eventual publication commit. After publication, the
implementation ledger records that commit, avoiding a circular hash.

### 7. Staging is local, path-confined, and never publication

M6.3 adds `/.m6-staging/` to `.gitignore`. The runner writes only beneath
`.m6-staging/<capture_id>/`, refuses symlinks and path traversal, creates a capture directory exclusively, and never
deletes or overwrites an earlier attempt. Test record/checkpoint roots are children of that directory. A rerun uses
a new capture id.

The staging attempt lifecycle is append-only:

`planned → preflighted → running → complete | failed | indeterminate → sanitized → reviewed-for-publication`.

M6.3 offline execution may reach `sanitized`; `reviewed-for-publication` requires a human review event and does not
mean independently reviewed. Terminal execution states never return to `running`. Every failed or indeterminate
attempt remains in the failure table and cannot be hidden by a later success.

The runner never stages, commits, pushes, copies into `docs/m6/captures/`, writes `records/`, or edits an existing
public capture. A later M6.4 materialization is a separately approved operation after exact-diff review.

### 8. Public artifacts are fixed projections, not redacted raw records

The runner constructs public objects field-by-field from purpose-built bounded results. It never implements a
generic “copy then redact” path. It may read verifier results and the bounded projections named by the schemas; it
may not ingest raw WAL/action/access JSONL, the services ledger, quarantine, HTTP bodies/headers, provider errors,
environment files, browser storage, agent state, or developer-tool exports.

Sanitization fails if a candidate contains an unknown key, secret-bearing header/value, credential/token/MAC,
private key material, local absolute path or `file:` URI, raw transport/provider content, unlabelled live/fixture
evidence, unhashed asset, non-synthetic text, or a success-only summary that omits a failed/indeterminate attempt.
Digests and already-public verification key ids remain allowed by their exact schema fields.

`docs/m6/acceptance.md` is generated deterministically from the closed catalog. It maps all beats,
adversarial cases, seven baseline criteria, and thirteen test families using only `exercised`, `partial`,
`not_assessed`, and `not_applicable`. It preserves the specification's current gaps and cannot upgrade a family
because one command passed.

No public capture directory is created in M6.3. The implementation tranche may commit schemas, catalog,
and acceptance ledger only; all runner output remains in gitignored staging and is not an M6 capture.

### 9. Implementation boundary

After exact-SHA GO and separate maintainer approval, M6.3 implementation may add only:

1. the public schemas, closed case catalog, generated acceptance ledger, and documentation under `docs/m6/`;
2. the `m6-capture-plan` and `m6-offline-outcome` domain tags and ADR-007 amendment, without changing any existing
   digest;
3. MIT-licensed offline catalog/executor, validator, staging, projection, and sanitization tooling plus deterministic
   tests;
4. root scripts for schema validation, offline execution, and dry-run only;
5. `/.m6-staging/` ignore coverage; and
6. the nine carried M6.2 services/browser test assertions.

It may refactor test helpers only when production semantics stay byte-equivalent. It may not add or change a
runtime route, ACL, policy rule, mandate/proposal/ruling/record schema, authority transition, provider adapter,
live runner, checkpoint writer, model card, generated record, or external effect.

## Acceptance tests

The M6.3 implementation is acceptable only if deterministic tests prove:

1. the catalog contains exactly 22 beat ids, every atomic adversarial id above, the nine infrastructure ids, and
   the explicit subdelegation exclusion; unknown/missing/duplicate ids fail;
2. every beat/adversarial executor genuinely runs under both distinct initial card bindings, every infrastructure
   row runs once, and the registry/catalog join is bijective;
3. every `invariant` pair has one matching outcome digest; every `provider_specific` pair is limited to beat 20 or
   an enumerated provider-projection fixture and matches both exact lane expectations, with no unexpected Commit,
   effect, authority broadening, or disclosure;
4. all five public schemas reject unknown keys and invalid versions; the relevant schemas also reject unsorted or
   duplicate sets, malformed digests, forbidden paths/content, and success-only omission;
5. plan digest vectors use the new domain and fail on any field, command, lane order, provenance, ceiling, or
   expected-boundary mutation;
6. offline and dry-run entry points make zero network/provider/probe/checkpoint/git operations and accept no live
   option; injected network/process calls fail the test;
7. all writes resolve inside one new staging capture directory; traversal, symlink, collision, overwrite, and
   writes to `records/`, `docs/m6/captures/`, or `.git/` fail;
8. lifecycle transitions are append-only and legal; failures/indeterminacy remain represented after later runs;
9. fixed projections and sanitization exclude every prohibited source/key/value class while retaining exact
   allowed digests and public verification ids;
10. the acceptance Markdown is byte-for-byte reproducible from the catalog and preserves every partial,
    not-assessed, and not-applicable boundary;
11. focused tests directly traverse every carried M6.2 services/browser guard/header and pin the exact route
    inventory; and
12. `npm run typecheck`, `npm test`, `npm run cards:verify`, schema validation, offline execution, dry-run,
    `git diff --check`, and generated-file drift checks pass with cards, Charter pins, records, and checkpoints
    unchanged.

## Deferred and excluded

M6.3 does not authorize or implement live provider/screening calls, live capture, checkpoint creation/commit/push,
capture materialization/publication, probe/key/card operations, real data, external effects, retries/fallbacks,
model ranking, semantic quality claims, independent-review claims, M6 completion, M6.5 authority-basis/source-
admissibility work, or M7 article claims.

The live approval envelope, published plan instance, `runtime:start` capture entry point, bounded provider request
accounting, self-declared review attestation, remotely acknowledged anchors, screenshots/clips, public capture
directory, and publication workflow remain M6.4.

## Consequences

M6.3 can establish that the pinned mechanism exercised its declared gates under fixed synthetic evidence and that
the public artifact contract cannot silently absorb raw runtime or secret material. It cannot establish that either
model is better, that live screening detects a class reliably, that the policy is legitimate, or that the result is
independent assurance.

The closed catalog and shared executor make missing and vacuous rows visible. The cost is a larger deterministic
test harness and a deliberately separate later live runner, but that separation preserves the approval boundary
between proving an offline mechanism and contacting external providers.
