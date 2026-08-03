<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ai-charter-runtime

A runnable proof of concept of the [Our AI Charter runtime reference model](https://robertschaub.github.io/our-ai-charter/wip/runtime-gates-poc-spec/):
at an AI prompt, the action path **plan → prepare → check → decide → review** executes with five gates
(**Authorize → Submit → Verify → Commit → Rely**) enforced *outside* the acting model — machine verdicts
**allow / deny / escalate**, automatic escalation to a human console carrying a six-field intervention
contract, two selectable acting-model evidence entries (with governed switching still an M5 task), and hash-chained action records
sealed before effect.

The authoritative build specification lives in the documentation repository:
[runtime-gates-poc-spec.md](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md).
On any divergence, the specification and its linked Charter source documents prevail.
The exact upstream revision, digest, reviewed runtime baseline, and remaining milestone work are tracked in
[docs/implementation-plan.md](docs/implementation-plan.md); the offline M4 beat and adversarial mapping is in
[docs/m4-acceptance.md](docs/m4-acceptance.md).

## Honest limits — read this first

- **Not an assurance or certification claim.** This demonstrates a runtime *mechanism*. Nothing here is
  "Charter-certified"; there is no green light, no trust API, no queryable certification (see [NOTICE](NOTICE)).
- **Institutions are simulated — two roles are absent.** Rulemaker, operator, and record keeper are surfaces
  played by one person; independent reviewer and remedy decider do not exist here. M4 now has a native
  three-process HTTP boundary and an authorization-origin governance console, but same-machine process
  isolation is separation of duties in miniature, not independence. M5.1 adds a deterministic,
  authorization-owned conversation transition and projection core, but provider ingress, empathy triggers,
  and governed switching are not active yet.
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
| `packages/adapters/` | OpenAI-compatible model adapters (MIT) | M3 |
| `packages/services-mock/` | Executing services with commitment verification (MIT) | M3 |
| `packages/consoles/` | M3 deterministic loop, M4 orchestrator process, governance console, and case-session handoff assets (MIT) | M3–M4 |
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

After `.env.local` contains the ADR-002 credentials and ADR-007 HMAC pair, start the local
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
record-verification, chain-view, and applicant-extract projections. The governance console at
`http://127.0.0.1:7801/console` now provides the principal mandate/card/escalation/record surfaces and the
applicant extract, plus the case officer's user-initiated handoff control. It has no third-party content,
emits no CORS headers, stores a pasted role token only in that origin's `localStorage`, and presents evidence
rather than an assurance signal. The applicant can append an extract-bound factual correction, which withdraws
reliance pending a principal-owned routing obligation without rewriting the effect. The handoff opens the fixed orchestrator-origin receiver, consumes a
maximum-30-second boot-bound code over the authenticated process channel, and creates an independent
maximum-15-minute session whose raw bearer is kept only in that tab's `sessionStorage`. That case surface now
shows the mandate's signed-card evidence, requires a local evidence check before preparing a model choice,
and polls only the authorization-owned ruling-status projection. A safe link opens the routed dialogue on the
authorization origin, where the responder's own role token reads the question/contract and posts the answer
directly. Raw clients still face the same ACL, Origin guard, evidence resolution, and single-use state machine.
The browser message route remains explicitly closed until the later M5 model/screening/empathy loop is
implemented. M4 acceptance is complete at reviewed runtime commit `e326562`; the M5.1 conversation-state
and pure projection core is an unreviewed implementation candidate and does not make a provider call.

Offline and deterministic verification uses synthetic records and skips only the remote-presence step:

```powershell
npm run verify:records -- --local
```
