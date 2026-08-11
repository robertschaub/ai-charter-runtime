<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ai-charter-runtime

A runnable proof of concept of the [Our AI Charter runtime reference model](https://robertschaub.github.io/our-ai-charter/wip/runtime-gates-poc-spec/):
at an AI prompt, the action path **plan → prepare → check → decide → review** executes with five gates
(**Authorize → Submit → Verify → Commit → Rely**) enforced *outside* the acting model — machine verdicts
**allow / deny / escalate**, automatic escalation to a human console carrying a six-field intervention
contract, two principal-approved acting-model evidence entries, an authorization-owned browser-initiated
selection/switch protocol, a reviewed native selected-lane call into sealed quarantine, reviewed M5.10
authorization-owned message ingestion and single-use output release, and hash-chained action records sealed before
effect. M5.11, reviewed at `8364745`, adds governed proposal intake and fixed pre-commit evidence. M5.12, reviewed
at `5b27b0e`, adds an authorization-derived dialogue trigger and response-bound native proposal revision; it still
cannot reach Commit or effect execution. [ADR-016](docs/adr/ADR-016-m6-evidence-capture.md) now proposes the M6
full-pass, authorization-owned live-screening, native commitment-continuation, and dual-model capture contract; no
M6 implementation, live run, checkpoint push, or capture artifact exists yet.

The authoritative build specification lives in the documentation repository:
[runtime-gates-poc-spec.md](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md).
On any divergence, the specification and its linked Charter source documents prevail.
The exact upstream revision, digest, reviewed runtime baseline, and remaining milestone work are tracked in
[docs/implementation-plan.md](docs/implementation-plan.md); the offline M4 beat and adversarial mapping is in
[docs/m4-acceptance.md](docs/m4-acceptance.md), and the bounded M5 acceptance evidence is in
[docs/m5-acceptance.md](docs/m5-acceptance.md).

## Honest limits — read this first

- **Not an assurance or certification claim.** This demonstrates a runtime *mechanism*. Nothing here is
  "Charter-certified"; there is no green light, no trust API, no queryable certification (see [NOTICE](NOTICE)).
- **Institutions are simulated — two roles are absent.** Rulemaker, operator, and record keeper are surfaces
  played by one person; independent reviewer and remedy decider do not exist here. M4 now has a native
  three-process HTTP boundary and an authorization-origin governance console, but same-machine process
  isolation is separation of duties in miniature, not independence. M5.2 is reviewed at `1973515` with
  authorization-resolved acting projections and deterministic fixture-pinned screening. The M5.3 boundary was
  reviewed at `1cc7fb2`; it adds non-authorizing, access-recorded lexical output admission, but an admitted result
  is not semantic red-line clearance. M5.4 is reviewed at `b247d5b`; it adds a containment-only coordinator
  exercised against a synthetic loopback provider. M5.5 is reviewed at `1d992fa`; it adds authorization-owned,
  durable, metadata-only evidence for each attempt before disclosure and for its terminal admission or fixed failure.
  M5.6 is reviewed at `b57c01e`; it adds an authorization-owned, replayable system-use decision prerequisite and a
  principal-only read view. Approval is necessary for the synthetic use but never sufficient for an action.
  The authorization gate and principal read view are wired into `runtime:start`. M5.9, reviewed at `e58d397`,
  adds a two-step, dynamic-session-only selected-lane call whose admitted bytes remain sealed and unreadable.
  M5.10, reviewed at `8a904f3`, adds a separate session-bound message preparation/use path, authorization-owned
  `said`/`inferred` ingestion, and a short-lived single-use release with consume-time currentness checks. The
  reviewed ADR-013 definition at `fbc72cc` now has a bounded M5.11 implementation reviewed at `8364745`: one explicit
  proposal preparation, a purpose-bound schema call, authorization-owned freeze, and fixed Authorize → Submit →
  Verify evidence. The separately reviewed ADR-014 definition at `0c3cac9` now has an M5.12 implementation reviewed
  at `5b27b0e`:
  authorization resolves the exact inferred dialogue item, owns a single-use revision preparation, and re-runs the
  revised proposal through the same three pre-commit gates. Neither path is an assurance, commitment, effect, or
  completed M5 path. M5.7, reviewed at
  `442397a`, adds replayable
  headless selection and switching through orchestrator-authenticated authorization routes. M5.8, reviewed at
  `ff9e438`, adds a dynamic-session-only browser caller with a two-minute, single-use preparation, redacted
  recovery, and no model request as part of selection. The M5.12 Verify-stage
  `unconfirmed_inference_as_fact` trigger is the only active native empathy dialogue path; broader semantic
  red-line coverage remains partial or not assessed. ADR-015's definition received exact-SHA GO at `a08fa98`.
  The bounded M5.13 implementation at `5251500` received exact-SHA GO with no findings and completes M5 only for
  this POC's stated acceptance boundary. It adds only the exact beat-5 fixture/test and acceptance ledger: no route,
  model capability, Commit, or effect path. Four empathy red-line families remain partial and two not assessed.
- **A deterministic gate proves declared rules were applied** — not that the rules are lawful, fair, or legitimate.
- **Commit-token window (interpretive choice).** Commitment binds at `commit-verify`; a revocation landing in the
  token's short TTL is too late for that action by definition. On the stricter reading of "authority in flight",
  that is a knowing, TTL-bounded divergence — recorded, not hidden.
- **A terminal `no-effect` reconciliation is append-only.** If later evidence proves an effect occurred, the
  terminal record is not overwritten; M4 must append a linked correction and route it for review.
- **Provider-side model substitution is detectable, not preventable**; the served-model id is itself
  provider-supplied evidence.
- **Screening models fail.** Their signals can only Flag or force Escalate — never allow.
- **Minimal cryptography** (hash chains + HMAC; composite-head checkpoints pushed to this public repo bound —
  but do not eliminate — the rollback window). Split custody is future work.
- **Synthetic scenario, demo-grade authentication, free-tier model endpoints without an SLA.**

## Layout and status

| Path | Content | Milestone |
|---|---|---|
| `docs/adr/` | Architecture decision records (protocol state machines, interfaces, anchoring, dialogue channel, classification, card lifecycle, canonicalization) | M1 |
| `docs/cards/` | Signed model cards (version-pinned evidence-registry artifacts) | M3 |
| `tooling/probe.mjs` | M0 capability probe (endpoints, model ids, `tools`, `response_format`, latency, limits) | M0 |
| `packages/gate-core/` | Authorization service — the independent gate (AGPL-3.0-only) | M2 |
| `packages/adapters/` | OpenAI-compatible model adapters (MIT) | M3–M5 |
| `packages/services-mock/` | Executing services with commitment verification (MIT) | M3 |
| `packages/consoles/` | M3 deterministic loop, M4 process/consoles, and M5 selected-lane ingress into sealed quarantine (MIT) | M3–M5 |
| `fixtures/` | Synthetic grant-scenario data and pinned test fixtures (MIT) | M3+ |

Licensing is per-directory — see [LICENSE.md](LICENSE.md).

## M0 probe

```bash
cp .env.local.example .env.local   # add your keys (never committed)
node tooling/probe.mjs --lane all
```

Results land in `docs/m0-probe-results.json` (gitignored); conclusions go into
[docs/m0-probe-memo.md](docs/m0-probe-memo.md).

## M4 native process boundary

After `.env.local` contains the ADR-002 credentials, ADR-007 HMAC pair, and both model-lane API keys, start the local
services, authorization, and orchestrator processes in fail-closed recovery order with:

```powershell
npm run runtime:start
```

The supervisor passes each child only its scoped credentials and derives narrower audience tokens in
memory. Services recovers its ledger first so authorization can replay, sweep, and reconcile before its
own listener binds. Authorization verifies the record layer against the last composite checkpoint before
appending the new run header; detected tampering or rollback halts startup, while remote unavailability is
reported without being confused with missing authority. The orchestrator binds last. Shutdown handlers are
installed before the first spawn, and supervised children close when their IPC parent disconnects. All listeners
use `127.0.0.1` by default.
The authorization-origin read-side APIs now serve strict ruling, model-card, mandate, escalation,
record-verification, chain-view, applicant-extract, and system-use-decision projections. The governance console at
`http://127.0.0.1:7801/console` now provides the principal mandate/card/escalation/record surfaces and the
applicant extract, plus the case officer's user-initiated handoff control. It has no third-party content,
emits no CORS headers, stores a pasted role token only in that origin's `localStorage`, and presents evidence
rather than an assurance signal. The applicant can append an extract-bound factual correction, which withdraws
reliance pending a principal-owned routing obligation without rewriting the effect. The handoff opens the fixed orchestrator-origin receiver, consumes a
maximum-30-second boot-bound code over the authenticated process channel, and creates an independent
maximum-15-minute session whose raw bearer is kept only in that tab's `sessionStorage`. That case surface now
shows the mandate's signed-card evidence and current authorization-owned selection. A distinct evidence-review
gesture asks the orchestrator to derive the current predecessor and obtain a fresh authorization check; only the
resulting process-private, maximum-two-minute preparation can be selected once. The browser receives neither the
  check id nor authorization-only bindings, stores no model target/selection preparation, and polls only authorization-owned
  state. The M5.9 implementation reviewed at `e58d397` adds a separate prepare/run gesture over the current
  selection. It uses only authorization's current synthetic projection, fixes the output ceiling at 512 tokens,
  returns metadata-only disclosure status, and leaves admitted bytes in a process-private no-reader quarantine.
  The M5.10 implementation reviewed at `8a904f3` preserves that projection-only route while adding a distinct
  two-step message composer. For a
  message-bound call, authorization ingests the officer text before provider contact, issues a release only with an
  admitted exact binding, and consumes it into the inferred store before the browser can read the labelled
  authorization transcript. The browser receives neither raw provider response nor release reference. A safe link opens the routed dialogue on the
authorization origin, where the responder's own role token reads the question/contract and posts the answer
directly. Raw clients still face the same ACL, Origin guard, evidence resolution, and single-use state machine.
This M5.10 path was reviewed at `8a904f3`; it does not complete M5. ADR-013 defines the separately approved bounded
proposal-intake slice; its initial definition review found two documentation-contract issues and the correction
received GO at `fbc72cc`. The implementation and its retry-idempotency regression were reviewed at `8364745` with
no remaining findings; the path remains bounded before Commit and does not complete M5. M4 acceptance
is complete at reviewed runtime commit `e326562`; the M5.1 conversation-state and pure projection core was
cross-model adversarially reviewed at `c1b5eb0` with no code findings. M5.2 was reviewed at `1973515`; it adds an
access-recorded, orchestrator-only acting projection and offline screening fixtures keyed to an exact frozen
proposal hash and gate. M5.3 was implementation-reviewed at `1cc7fb2`; it recomputes that projection before
accepting a synthetic model-output claim, checks current mandate/card and requested-versus-served model identity,
derives turn-level restriction tags inside authorization, and records only decision metadata and digests. Its
narrow lexical checker can miss paraphrases, so admission is not a semantic safety clearance. It returns no ruling
  or token, makes no provider call, leaves the browser route at `501`, and does not complete M5. M5.4
connects an authorization projection to a synthetic loopback adapter and returns the response to authorization;
an admitted result is held behind a process-private metadata/destroy-only quarantine with no release path. This
coordinator was not constructed by the runtime process in that reviewed slice. The M5.5
integration point reviewed at `1d992fa` replaces the raw projection route with a single-use call lifecycle:
authorization durably records the turn/mandate/card/model/projection binding before returning the projection, then
records admitted, withheld, or a fixed failure class without raw output, prompts, provider errors, endpoints, or
credentials. Expired, replayed,
mismatched, and previous-boot references fail closed; an unfinished attempt remains explicitly indeterminate after
recovery. This evidence does not release output, call a live provider, or complete M5.
M5.6, reviewed at `b57c01e` after its evidence-derivation correction, additionally requires one exact, current
system-use decision at the case, model-call, ruling/commit, and record/receipt boundaries. It binds only decision
id/version/digest, bounded status/condition
facts, and current-at-record results; evidence packs and rationale stay out of runtime records. A transition
invalidates outstanding rulings and blocks post-provider admission without releasing or persisting the output.
The principal view is read-only evidence, not a trust score, certification, legal approval, or action authority.
M5.7, reviewed at `442397a`, replaces the legacy proposal-time selection marker with one append-only,
authorization-owned current selection per configured case. Boot-bound single-use checks precede initial selection
or switching; selection identity binds calls, admission, proposals, rulings, and commitment verification. A switch
atomically retires unresolved prior-lane rulings and calls, while served identity is appended only from confirmed
terminal call evidence. M5.8, reviewed at `ff9e438`, connects that protocol only to the authenticated case console.
It keeps the authorization check and predecessor server-side, derives case-seat provenance from the session, and
recovers only through a redacted current-selection read. It adds no native provider ingress, conversation
ingestion, output release, live probe, or M6 path.
M5.9, reviewed at `e58d397`, constructs the two signed-card-bound adapters and coordinator before the orchestrator
listener binds, gives provider configuration only to that child, and exposes single-use preparation/use/status
routes to the dynamic case session. Startup itself makes no provider request, no live provider invocation was run
for that tranche. M5.10, reviewed at `8a904f3`, adds the separately defined message-ingress, release, and transcript
path without proposal construction, empathy completion, a live provider run, or M6 capture. M5.11, reviewed at
`8364745`, implements only ADR-013's native proposal preparation, schema-bound intake/freeze, replayable origin evidence,
fixed precommit sequence, and exact-key browser projection. M5.12, reviewed at `5b27b0e`, implements only ADR-014's focused
Verify dialogue trigger, direct response basis, revision preparation/use, immutable successor lineage, and repeated
precommit checks. It makes no live provider claim and never reaches Commit or an executing service. The M5.13
implementation reviewed at `5251500` adds fixture-pinned beat-5 conformance and an honest acceptance map. This
completes the bounded M5 milestone, not the partial or unassessed areas recorded in that map. ADR-016 is a
definition-only M6 proposal. It preserves those limits and requires separate reviewed implementation, action-time
live-provider approval, checkpoint-push approval, artifact review, and publication approval.

Offline and deterministic verification uses synthetic records and skips only the remote-presence step:

```powershell
npm run verify:records -- --local
```
