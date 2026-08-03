<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ai-charter-runtime

A runnable proof of concept of the [Our AI Charter runtime reference model](https://robertschaub.github.io/our-ai-charter/wip/runtime-gates-poc-spec/):
at an AI prompt, the action path **plan → prepare → check → decide → review** executes with five gates
(**Authorize → Submit → Verify → Commit → Rely**) enforced *outside* the acting model — machine verdicts
**allow / deny / escalate**, automatic escalation to a human console carrying a six-field intervention
contract, two user-selectable acting models with governed switching, and hash-chained action records
sealed before effect.

The authoritative build specification lives in the documentation repository:
[runtime-gates-poc-spec.md](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md).
On any divergence, the specification and its linked Charter source documents prevail.
The exact upstream revision, digest, reviewed runtime baseline, and remaining milestone work are tracked in
[docs/implementation-plan.md](docs/implementation-plan.md).

## Honest limits — read this first

- **Not an assurance or certification claim.** This demonstrates a runtime *mechanism*. Nothing here is
  "Charter-certified"; there is no green light, no trust API, no queryable certification (see [NOTICE](NOTICE)).
- **Institutions are simulated — two roles are absent.** Rulemaker, operator, and record keeper are surfaces
  played by one person; independent reviewer and remedy decider do not exist here. M4 now has a native
  three-process HTTP boundary and an authorization-origin governance console, but same-machine process
  isolation is separation of duties in miniature, not independence; the case console remains unfinished.
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
| `packages/consoles/` | M3 deterministic loop, M4 orchestrator process, and authorization-origin governance-console assets (MIT) | M3–M4 |
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
applicant extract. It has no third-party content, emits no CORS headers, stores a pasted role token only in
that origin's `localStorage`, and presents evidence rather than an assurance signal. The case console,
credential-bearing dialogue response control, and approved one-time browser credential handoff are not yet
built; their pinned protocol and order are recorded in the implementation plan.

Offline and deterministic verification uses synthetic records and skips only the remote-presence step:

```powershell
npm run verify:records -- --local
```
