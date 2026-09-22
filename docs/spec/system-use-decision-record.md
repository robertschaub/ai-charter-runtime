<!-- SPDX-License-Identifier: CC-BY-4.0 -->

> **Status: CURRENT SPECIFICATION** — pre-ingress companion to the runtime-gates POC; not a certification, legal approval, or operating service.

# System-use decision record — pre-ingress specification

## Purpose

Before an AI system is used in a bounded workflow, a responsible institution should be able to show why that exact system, version, configuration, and use-case may be used, on which evidence, under whose decision, for how long, and with which re-check triggers. The record defined here joins that lifecycle decision to the Charter's runtime gates without turning it into action authority.

For the POC, the rule is:

> **A current system-use decision is necessary for use, but never sufficient to authorize an action.**

The authorization service still decides each consequential transition against the current mandate, policy, evidence, and system state. An approved system-use record can only satisfy one admissibility precondition; it cannot mint a mandate, ruling, commitment token, or effect.

## Keep four decisions distinct

| Decision | Question | Authority | POC treatment |
|---|---|---|---|
| **System-use decision** | May this exact system and configuration be used for this bounded purpose? | The institution accountable for the deployment or use | This note: a scoped, expiring, reviewable prerequisite. |
| **Legal or conformity decision** | Does an applicable legal or sectoral route permit placing, deploying, or using it? | Regulators, courts, notified bodies, and other legally empowered actors | Referenced where applicable; never decided by the Charter or POC. |
| **Charter assurance claim** | What independently reviewed public claim may be made about the assessed release? | A future independent assurance structure, if one is created | Absent from the POC; no certification, alignment, mark, or trust badge. |
| **Runtime authorization** | May this exact consequential action proceed now? | Current mandate plus independent policy enforcement and any authorized human intervention | The existing **allow / deny / escalate** gates; never inferred from the system-use decision. |

## POC scope

The first implementation should use one checked-in synthetic decision fixture for the public-grant scenario. It should prove binding, expiry, supersession, suspension, withdrawal, replay recovery, and fail-closed enforcement. It should not build a general organisational approval workflow, accept real personal data, or claim that the evidence pack was independently assessed.

The POC record is authorization-owned. A provider, model, orchestrator, case browser, or service must not be able to create it, select its scope, assert its status, narrow its conditions, or choose which version is current.

## Record shape

The implementation repository should freeze the exact JSON schema in an ADR before code. This YAML shows the required semantics, not wire syntax:

```yaml
schema: our-ai-charter/system-use-decision@1
decision_id: sud_public_grant_v1
version: 1
world_id: demo
use_case_id: public-grant-decision

subject:
  system_id: ai-charter-runtime-poc
  configuration_digest: sha256-of-material-runtime-configuration
  policy_version: policy-v1
  model_cards:
    - card_id: publicai-apertus-v1.5-70b
      card_version: 1
      card_digest: exact-signed-content-digest
      roles: [acting, screening]
  data_classes: [conf:public, conf:case, purpose:grant-assessment]
  jurisdictions: [synthetic-demo]

purpose:
  need: demonstrate-evidence-bound-runtime-governance
  expected_outcome: exercise-the-five-gates-with-synthetic-data
  success_measures:
    - all-required-beats-and-adversarial-cases-pass
  non_ai_or_less_harmful_alternative: fixed-fixture-only-demonstration
  affected_groups: [synthetic-applicant]

evidence_refs:
  - type: release-risk-assessment
    ref: checked-in-synthetic-fixture
    digest: sha256
    provenance: synthetic_fixture
    evidence_depth: documented
    as_of: 2026-08-04
    limitations: [not-independently-assessed]
  - type: impact-assessment
    ref: not-assessed-in-poc
    provenance: synthetic_fixture
    evidence_depth: not_assessed
    as_of: 2026-08-04
    limitations: [no-real-deployment-or-affected-person]
  - type: testing-and-validation
    ref: named-test-ledger
    digest: sha256
    provenance: probe_tested
    evidence_depth: implementation_checked
    as_of: 2026-08-04
    limitations: [synthetic-services-and-fixtures]
  - type: monitoring-and-response
    ref: named-monitoring-plan
    digest: sha256
    provenance: self_declared
    evidence_depth: documented
    as_of: 2026-08-04
    limitations: [poc-only]

decision:
  status: approved_with_conditions
  authority_role: principal
  basis_summary: synthetic-poc-use-only
  conditions:
    - id: synthetic-data-only
      kind: hard_precondition
    - id: no-external-effect
      kind: hard_precondition
  unresolved_findings: []
  residual_risk:
    disposition: not_assessed
    authority_role: principal

validity:
  effective_at: 2026-08-04T00:00:00Z
  expires_at: 2026-09-30T00:00:00Z
  review_cadence: before-each-live-capture
  redecision_triggers:
    - material-policy-change
    - model-card-supersession-or-revocation
    - material-runtime-configuration-change
    - evidence-withdrawal
    - repeated-failure-or-incident

accountability:
  mission_owner_role: principal
  technical_owner_role: operator
  independent_challenger_role: not_available_in_poc
  remedy_owner_role: not_available_in_poc

trace:
  record_digest: sha256
  evidence_pack_ref: role-scoped-reference
  created_at: 2026-08-04T00:00:00Z
  supersedes: null
  challenge_route: synthetic-applicant-challenge-route
```

`evidence_depth` reuses the Charter vocabulary: **documented**, **evidence observed**, **implementation checked**, **effectiveness tested**, or **not assessed**. POC provenance remains limited to **synthetic fixture**, **self-declared**, or **probe-tested**. Nothing in this record may be labelled independently attested.

## Invariants

1. **Necessary, never sufficient.** `approved` or `approved_with_conditions` satisfies only system-use admissibility. The normal mandate, policy, screening, escalation, commitment, and effect checks still apply.
2. **No caller assertion.** Runtime callers submit only the identifiers already required for their operation. Authorization resolves the current decision and its scope internally.
3. **Exact binding.** World, use-case, configuration digest, policy version, model-card versions and digests, roles, data classes, and validity must match. A broader, stale, substituted, missing, or ambiguous binding fails closed.
4. **Conditions are enforceable or visibly unresolved.** A `hard_precondition` must be machine-resolved by authorization; free text cannot grant use. An unresolved hard condition blocks use.
5. **Honest evidence status.** Missing evidence is `not_assessed`, not silently absent or represented as satisfied. A digest proves object identity, not truth, sufficiency, legitimacy, or independent review.
6. **Append-only decision history.** Correction or restoration creates a successor version. Historical decisions and transitions remain reviewable; they are not overwritten.
7. **No trust surface.** The console may show the scoped decision, evidence depths, limitations, conditions, and currentness. It must not expose a green badge, aggregate trust score, or queryable certification result.
8. **Privacy-minimal projection.** Provider messages, public receipts, action records, and access records carry only the decision id, version, digest, bounded status facts, and necessary condition results. They do not copy the evidence pack, rationale detail, prompts, outputs, or personal data.
9. **Withdrawal can only narrow.** Suspension, withdrawal, expiry, missing current evidence, or integrity failure blocks new use and cannot be overridden by model output or a caller-supplied field.

## Lifecycle

The durable state machine is:

```text
proposed → approved | approved_with_conditions | rejected
approved | approved_with_conditions → superseded | suspended | withdrawn | expired
```

`rejected`, `superseded`, `suspended`, `withdrawn`, and `expired` are terminal for that version. Resumption requires a new successor decision. Expiry is evaluated from the timestamp at every decision boundary; a sweeper may record the transition for observability but must not be required for safety.

For this POC, any change away from a current approved state fails closed for unresolved work:

- new case creation and **Plan → Authorize** stop;
- `model-calls/begin` returns no projection, so no provider disclosure starts;
- an already-open model call cannot admit or release output after the decision changes;
- an uncommitted ruling fails current-state verification at `commit-verify`;
- an already committed effect is not rewritten, but its reliance may be reopened, corrected, constrained, or withdrawn through **Rely**.

This strict rule favours testable containment over availability. A later design may distinguish ordinary successor review from urgent suspension, but that is outside the first POC slice.

## Runtime integration

Authorization owns the record and checks it at five boundaries:

1. **Case creation / Authorize** — resolve one current decision for the configured world and use-case before a mandate can start a new case.
2. **Model-call begin** — before returning projected items, bind the decision id, version, and digest into the durable `model_call.open` record.
3. **Output admission** — re-resolve current state; a changed or unusable decision terminates the call without conversation persistence or browser release.
4. **Ruling and commitment** — bind the decision reference into the ruling; `commit-verify` rechecks current status and exact scope before effect.
5. **Record and receipt** — preserve the reference, check result, and currentness without copying the evidence pack.

The decision state belongs in the authorization WAL and replay model. The checked-in synthetic fixture may enter only through an authorization-process-only startup seam. A browser or HTTP mutation route is a separate later slice requiring its own authority, schema, access-control, and adversarial review.

## Acceptance tests for the first slice

The slice is not complete unless tests show:

1. missing, rejected, expired, suspended, withdrawn, or integrity-invalid decisions disclose nothing and fail closed;
2. wrong world, use-case, configuration, policy, model card, role, data class, version, or digest fails closed;
3. an approved decision alone cannot create a mandate, ruling, commitment token, or effect;
4. callers cannot submit or override decision status, scope, evidence depth, conditions, or current version;
5. an unmet hard condition blocks case creation and model-call begin;
6. a change after `model_call.open` prevents admission and leaves no quarantined or conversation item;
7. a change after ruling but before `commit-verify` prevents commitment;
8. replay reconstructs the same current decision and refuses terminal-version reuse or rollback;
9. only bounded references and condition results enter model-call, action, access, and receipt records;
10. the full evidence pack, rationale detail, prompts, outputs, and credentials never enter provider projection or public records;
11. the console labels every POC evidence item synthetic, self-declared, probe-tested, or not assessed and makes the absent independent reviewer and remedy decider visible;
12. the existing M5.5 model-call lifecycle tests remain unchanged and green before this new slice begins.

## Implementation order

1. Finish and exact-SHA review M5.5 unchanged, then stop.
2. Freeze the decision schema and lifecycle in an ADR in `ai-charter-runtime`; update that repository's immutable specification pin only after this upstream change is reviewed and published.
3. Implement authorization-owned schema, WAL/replay, synthetic fixture, and read-only projection with no browser or provider release path.
4. Add fail-closed checks at case creation, model-call begin/admission, ruling binding, and `commit-verify`.
5. Add the scoped governance-console view only after the core state and negative tests pass.
6. Complete remaining M5 ingress, dialogue, switching, and release work; M6 captures the already-frozen behaviour and introduces no new governance semantics.

## Honest limits

This record demonstrates that a declared decision and its evidence references constrained the POC. It cannot establish that the purpose is legitimate, the evidence sufficient, the risk acceptable, the decision-maker independent, or an effective remedy available. The synthetic POC has no real deployment, applicant, legal authority, independent assessor, or remedy decider.

The record is also not an ISO/IEC 42001 certificate, an ISO/IEC 42005 impact assessment, an EU AI Act conformity decision, or a Charter assurance claim. Those sources support lifecycle management, impact assessment, documentation, testing, monitoring, and accountability, but their applicability and legal effect remain scope-specific.

## Source anchors

- [Charter Commitments](https://github.com/robertschaub/our-ai-charter/blob/main/docs/Assurance/Framework/charter-commitments.md) — release risk assessment, evidence depth, lifecycle control, accountable ownership, and the consequential-action baseline.
- [Assurance cases](https://github.com/robertschaub/our-ai-charter/blob/main/docs/Assurance/Concepts/assurance-cases.md) — the hard legitimacy gate and Claims → Arguments → Evidence structure.
- [User-workflow governance](https://github.com/robertschaub/our-ai-charter/blob/main/docs/Assurance/Concepts/user-workflow-governance.md) — **Plan → Authorize** and the human-intervention contract.
- [Runtime-gates POC specification](runtime-gates-poc-spec.md) — implementation authority, architecture, milestones, and honest limits.
- [NIST AI RMF 1.0 Core](https://airc.nist.gov/airmf-resources/airmf/5-sec-core/) — intended purpose, go/no-go decisions, testing, monitoring, responsibility, and decommissioning.
- [ISO/IEC 42001](https://www.iso.org/standard/42001) and [ISO/IEC 42005](https://www.iso.org/standard/42005) — AI management systems and lifecycle impact assessment.
- [EU AI Act](https://eur-lex.europa.eu/eli/reg/2024/1689/oj/eng) — scope-specific high-risk requirements for risk management, documentation, oversight, testing, accountability, and post-market monitoring.
- [Reza Ahoui's public practitioner post](https://www.linkedin.com/posts/reza-ahoui_aigovernance-responsibleai-iso42001-share-7483517300663332866-QXW3/) — the evidence-before-approval prompt that motivated this consolidation; not a normative source.
