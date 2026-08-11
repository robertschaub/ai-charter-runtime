<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-015 — Bounded empathy conformance and M5 acceptance

**Status:** definition reviewed GO at `a08fa98`; bounded implementation candidate awaiting exact-SHA adversarial
review.
**Spec:** §2 (empathy source), §4 (four-store items and screening signals), §5 (empathy layer, entry and
output boundaries, and model navigation), §7 beats 4–5 and 19–21, §8 test-family coverage, and §10 M5.
**Depends on:** ADR-002, ADR-004, ADR-005, ADR-009, ADR-012, ADR-013, and ADR-014.

## Context

M5.1–M5.12 now implement the specification's bounded screening, four-store conversation state, selected-model
transport, output-admission, governed proposal, and Verify-dialogue mechanisms. The reviewed M5.12 path resolves an
exact `unconfirmed_inference_as_fact` signal inside authorization, routes one focused question under the existing
dialogue contract, and may prepare a fresh proposal that re-runs Authorize → Submit → Verify. It cannot reach
Commit or effect.

Calling the remaining work "semantic empathy completion" would overstate the POC. The existing output check is a
deliberately narrow deterministic lexical control, an admitted output is not semantic red-line clearance, and the
authoritative specification explicitly permits test-family results to remain partial or not assessed when named
honestly. The published empathy source likewise defines the target as observable, grounded, correctable conduct
that protects agency—not a claim that an AI feels empathy.

One executable M5 gap remains inside the specification's own bounded scenario: beat 5 names an injected instruction
in an applicant document and requires `injection_suspicion` → Stop, but the checked-in screening fixture currently
exercises `evidence_conflict`, not that exact beat. The remaining work is therefore an acceptance and conformance
slice, not a new model capability, classifier, route, or authority path.

## Decision

### 1. "Empathy completion" is a bounded POC conformance claim

M5.13 completes only the M5 row and scripted beats of the pinned runtime-gates POC specification. It may show that
the runtime preserves testimony, inference, confirmation, and permission separately; makes a consequential
unconfirmed inference correctable before reliance; and withholds the narrow output patterns it actually detects.
It must not claim that the system is empathic, emotionally safe, semantically cleared, suitable for deployment, or
assured against all six red lines.

The implementation tranche adds an offline `docs/m5-acceptance.md` ledger. Every M5 requirement and empathy red-line
family is labelled **exercised**, **partial**, or **not assessed**, with executable evidence and the remaining gap.
The ledger carries forward the authoritative specification's test-family statuses rather than upgrading them from
repository structure or absence of a feature.

At minimum the red-line matrix records these boundaries:

| Published red line | M5 acceptance status and boundary |
|---|---|
| Claimed feelings or consciousness | **partial** — deterministic English patterns are exercised before release; paraphrases and other languages are not semantic-screened. |
| Telling a user the AI needs, misses, or loves them, or should replace human relationships | **partial** — the narrow relationship-dependency pattern is exercised; ordinary uses of words such as "love" are intentionally not treated as proof of dependency. |
| Biometric diagnosis of inner state as fact | **not assessed** — the POC has no biometric test family or general semantic detector. |
| Exploiting vulnerability for engagement, spending, disclosure, or compliance | **not assessed** — no behavioural or longitudinal evaluation is implemented. |
| Sensitive emotional memory or training reuse without explicit revocable permission | **partial** — the case-scoped `permitted` store and authorization-owned dialogue transition are exercised; persistent-memory products, training reuse, deletion propagation, and revocation usability are not assessed. |
| Emotional interpretation stated more confidently than evidence permits | **partial** — the exact Verify-stage grant-scenario inference is exercised through dialogue and re-gating; ordinary model prose has no general semantic interpretation detector. |

These labels are acceptance constraints. An implementation may narrow a label when evidence is weaker, but it may
not upgrade one without a separately reviewed definition and executable evidence.

### 2. Authorization remains the sole owner of the native empathy trigger

ADR-014's reviewed `unconfirmed_inference_as_fact` path remains the only native dialogue trigger in this POC. The
screening model or fixture supplies evidence only. It cannot choose the question, standing, eligible role,
substitute, permitted dispositions, safe default, gate, route, successor, or verdict. Authorization derives those
facts from exact current state and the frozen proposal.

Signal enrichment is monotone: it may raise an otherwise-allow result to Stop + escalate, and it may preserve or
narrow an existing escalation, but it must never lower, replace, or throw away a deny. The regression reviewed at
`5b27b0e` remains required. No new empathy rule may weaken this deny-precedence invariant.

### 3. Beat 5 receives one exact deterministic conformance fixture

The implementation tranche adds one synthetic frozen proposal whose exact suspect material item contains the
scripted applicant-document injection from beat 5. A separate exact proposal-hash + Submit-gate screening fixture
returns one `injection_suspicion` signal for that item. The fixture is deterministic test evidence, not a live
screening claim or a general prompt-injection detector.

The end-to-end assertion must prove all of the following:

- authorization derives the screening projection for the exact frozen proposal and Submit gate;
- the suspect item is inside the screening lane's current permitted projection;
- the exact `injection_suspicion` signal and projection evidence enter the ruling;
- the result is Stop + escalate and never allow;
- no later Verify, Commit, reservation, token, service call, or effect occurs; and
- a changed proposal hash, item, case, gate, or undisclosable suspect fails closed rather than reusing the fixture.

The existing generic "a signal never allows" unit test remains necessary but is not by itself evidence for beat 5.

### 4. M5.13 adds no runtime interface or authority path

M5.13 adds no production route, handler, schema, credential, model call, provider projection, ruling type, mandate
field, dialogue disposition, commitment, token, service call, effect, or persistent-memory/training capability.
ADR-002's reviewed inventory remains exactly twenty-one orchestrator process gate/data routes plus the dedicated
handoff redemption and close routes. The only authority-changing M5.11/M5.12 process mutation remains fixed
precommit; M5.13 adds none.

The implementation tranche is limited to synthetic fixtures, conformance tests, the M5 acceptance ledger, and
truthful status documentation. If those tests expose a production defect, implementation stops and proposes a
separate bounded correction; this definition does not pre-authorize production code changes.

### 5. Acceptance closes the milestone, not the unassessed areas

After the bounded implementation passes exact-SHA adversarial review, the plan and README may mark **M5 complete**
for this POC. The acceptance ledger must retain the partial and not-assessed boundaries next to that status. A
milestone label cannot be used as assurance, certification, safe-chat evidence, a real-user evaluation, or proof
that a provider model behaves empathically.

The reviewed M5.12 implementation remains the authority-bearing integration baseline until the conformance tranche
is reviewed. A documentation-only review acknowledgement may then record the GO result without recursively
reopening the reviewed source tree.

## Acceptance tests for the implementation tranche

- Add the exact beat-5 proposal and screening fixtures and prove the full Submit Stop path in §3 with synthetic data.
- Preserve the beat-4 native dialogue test: exact inferred item → authorization-derived question/contract →
  bare-confirm refusal → cited response → refreshed projection → new proposal → Authorize/Submit/Verify, with no
  Commit, reservation, token, service call, or effect.
- Preserve the deny-precedence regression and prove every screening signal remains unable to produce allow.
- Preserve output-admission and browser/process tests showing both implemented lexical reason classes withhold
  before release and never enter the authorization transcript; benign disclaimers remain outside the conservative
  match. The ledger states that this is partial lexical evidence, not semantic clearance.
- Preserve four-store schema, transition, projection, correction, and exact standing tests. Confirmation and
  permission remain case-scoped evidence, never action authority.
- Preserve the reviewed selection, provider-disclosure, conversation-ingress, proposal-intake, and substitution
  coverage for beats 19–21.
- Assert the authorization route inventory remains exactly twenty-one process gate/data routes, the orchestrator is
  denied on every authority-changing route other than fixed precommit, and no M5.13 route exists.
- Create `docs/m5-acceptance.md` mapping beats 4–5 and 19–21, all six empathy red lines, and the relevant test
  families to executable evidence and honest gaps.
- Run `npm run typecheck`, `npm test`, `npm run cards:verify`, and `git diff --check`. Tests use deterministic clocks,
  ids, synthetic fixtures, and loopback providers only.

## Deferred and excluded

General semantic red-line classification, emotional-state inference, vulnerability or manipulation evaluation,
affected-person studies, multilingual/paraphrase coverage, persistent memory, training reuse, permission-withdrawal
UX, deletion propagation, broader dialogue classes, dynamic Commit/effect initiation, live provider runs, M6
capture/publication, the anchoring-flow finding, and the general `reverse` disposition remain separate. None is
silently treated as implemented because M5 closes.

No live probe or provider call, key generation or rotation, model-card signing, generated/append-only record edit,
push, or upstream Charter edit is authorized by this ADR.

## Consequences

This decision makes the final M5 claim smaller but falsifiable. It closes the reference scenario with one missing
scripted screening beat and a durable evidence map, while preventing "empathy completion" from becoming a vague
claim of model quality the repository cannot support.

The tradeoff is visible incompleteness: all six red-line families remain partial or not assessed (four partial and
two not assessed). That is deliberate under the specification's honesty rule and leaves later work separable from
the POC's authority architecture.
