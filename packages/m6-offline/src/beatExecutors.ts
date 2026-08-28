// SPDX-License-Identifier: MIT
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  AuthorizationReadSide,
  compareServedId,
  freezeProposal,
  RecordVerificationError,
  recordVerificationAccess,
  type FrozenProposal,
  type Mandate,
  type RuleProposalResult,
  type ScreeningSignal,
  verifyRecords,
  writeCheckpoint,
} from 'gate-core/offline-safe';
import { ModelAdapterError } from 'model-adapters/offline-safe';
import { ModelTurnCoordinator, type ModelTurnAuthorizationClient, type ModelTurnLaneConfig } from 'runtime-consoles/offline-safe';

import { ProductionHarness, type ProductionHarnessOptions } from './productionHarness.js';
import { REPOSITORY_ROOT } from './repository.js';
import { boundedResult, gateObservation, interventionObservation } from './result.js';
import type { BoundedCaseResult, ScenarioContext } from './types.js';

const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: null } as const;
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const CASE_OFFICER = { credential: 'role:case_officer', claimed_role: 'case_officer' } as const;
const APPLICANT = { credential: 'role:applicant', claimed_role: 'applicant' } as const;
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;

function signal(kind: ScreeningSignal['signal'], suspectItemId?: string): ScreeningSignal {
  return {
    kind: 'screening_signal',
    signal: kind,
    ...(suspectItemId === undefined ? {} : { suspect_item_id: suspectItemId }),
    confidence_pct: 100,
    rationale: `Synthetic pinned ${kind} fixture.`,
    model_id: 'screening-model',
    model_version_reported: 'screening-model-v1',
  };
}

async function harnessFor(
  context: ScenarioContext,
  options: Partial<Omit<ProductionHarnessOptions, 'recordsRoot' | 'caseId' | 'laneSlot' | 'selectedCard'>> = {},
): Promise<ProductionHarness> {
  if (context.laneSlot === 'single' || context.selectedCard === null) throw new Error('beat executor requires a lane');
  return ProductionHarness.create({
    recordsRoot: context.recordsRoot,
    caseId: context.row.id,
    laneSlot: context.laneSlot,
    selectedCard: context.selectedCard,
    ...options,
  });
}

function successfulResult(
  context: ScenarioContext,
  gates: readonly RuleProposalResult[],
  fields: Partial<Pick<BoundedCaseResult, 'intervention' | 'commitment_state' | 'effect_count' | 'failure_class' | 'containment_class' | 'mechanism' | 'observed_assertions'>> = {},
): BoundedCaseResult {
  return boundedResult(context, {
    gates: gates.map(gateObservation),
    intervention: fields.intervention ?? null,
    commitment_state: fields.commitment_state ?? 'none',
    effect_count: fields.effect_count ?? 0,
    failure_class: fields.failure_class ?? null,
    containment_class: fields.containment_class ?? 'continued',
    mechanism: fields.mechanism ?? 'authorization-core',
    observed_assertions: fields.observed_assertions ?? [{ name: 'production_path_traversed', observed: true }],
  });
}

function modelAuthorization(harness: ProductionHarness): ModelTurnAuthorizationClient {
  const projections = harness.projections();
  return {
    currentModelSelection: async () => projections.currentSelection(ORCHESTRATOR),
    checkModelSelection: async (_world, _case, input) => projections.checkSelection({ ...input, actor: ORCHESTRATOR }),
    selectModel: async (_world, _case, input) => projections.selectModel({ ...input, actor: ORCHESTRATOR }),
    beginModelCall: async (input, onBehalfOf) => projections.beginCall({
      turn_id: input.turnId,
      selection_id: input.selectionId,
      ingress_binding: input.ingressBinding ?? null,
      proposal_binding: input.proposalBinding ?? null,
      revision_binding: input.revisionBinding ?? null,
      ...(onBehalfOf === undefined ? {} : { sessionId: onBehalfOf.session_id }),
      actor: ORCHESTRATOR,
    }),
    admitModelOutput: async (_world, callId, input, onBehalfOf) => projections.completeCall({
      call_id: callId,
      output: input,
      ...(onBehalfOf === undefined ? {} : { sessionId: onBehalfOf.session_id }),
      actor: ORCHESTRATOR,
    }),
    failModelCall: async (_world, input) => projections.failCall({ ...input, actor: ORCHESTRATOR }),
    consumeProposalIntake: async (_world, intakeId, content) => harness.proposalIntakes.consume(intakeId, content, ORCHESTRATOR),
    proposalIntakeStatus: async (_world, intakeId) => harness.proposalIntakes.status(intakeId, ORCHESTRATOR),
  };
}

function nativeProposalContent(materialInputId: string, derivedClaimIds: readonly string[] = []): string {
  return JSON.stringify({
    declared_objective: 'File the synthetic grant application.',
    proposed_action: 'Submit the synthetic grant filing.',
    target: { recipient: 'grant-office', resource: 'application-42' },
    exact_parameters: { amount_minor_units: 50, reference: 'm6-native-effect' },
    material_input_ids: [materialInputId],
    derived_claim_ids: derivedClaimIds,
    data_to_be_disclosed: ['applicant_name'],
    cost_obligation: { amount_minor_units: 50, description: 'Synthetic grant amount.' },
    material_consequences: ['Creates a synthetic public-funds commitment.'],
    reversibility_class: 'partially-reversible',
    commercial_influence: { applicable: false, note: 'Not applicable.' },
  });
}

function laneConfig(context: ScenarioContext, act: ModelTurnLaneConfig['adapter']['act']): ModelTurnLaneConfig {
  if (context.selectedCard === null || context.laneSlot === 'single') throw new Error('model boundary requires a lane');
  return {
    lane: context.laneSlot === 'lane-0' ? 'publicai' : 'openai',
    cardId: context.selectedCard.card_id,
    cardVersion: context.selectedCard.card_version,
    requestedId: context.selectedCard.requested_id,
    adapter: {
      lane: context.laneSlot === 'lane-0' ? 'publicai' : 'openai',
      requestedId: context.selectedCard.requested_id,
      act,
    },
  };
}

async function executeModelFailure(context: ScenarioContext, mismatch: boolean): Promise<BoundedCaseResult> {
  const harness = await harnessFor(context);
  try {
    let attempts = 0;
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: context.row.id.replaceAll('-', '_'),
      authorization: modelAuthorization(harness),
      lanes: [laneConfig(context, async () => {
        attempts += 1;
        if (!mismatch) throw new ModelAdapterError('provider-http', 'synthetic offline endpoint unavailable');
        return {
          lane: context.laneSlot === 'lane-0' ? 'publicai' : 'openai',
          requestedId: context.selectedCard?.requested_id ?? '',
          servedId: 'synthetic-unapproved-model',
          content: 'Synthetic output that must remain quarantined.',
          toolCalls: [],
        };
      })],
    });
    let failureClass = '';
    try {
      await coordinator.run({
        turnId: `turn_${context.row.id.replaceAll('-', '_')}_${context.laneSlot.replaceAll('-', '_')}`,
        selectionId: harness.selectionId,
        cardId: context.selectedCard?.card_id ?? '',
        cardVersion: context.selectedCard?.card_version ?? 1,
        requestedId: context.selectedCard?.requested_id ?? '',
        maxOutputTokens: 64,
      });
    } catch (error) {
      failureClass = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'provider-failure';
    }
    const call = [...harness.store.snapshot().modelCalls.values()][0];
    if (call === undefined || call.state !== 'terminal' || attempts !== 1 || coordinator.quarantine.size !== 0) {
      throw new Error('model failure containment did not materialize');
    }
    return boundedResult(context, {
      gates: [],
      intervention: null,
      commitment_state: 'blocked',
      effect_count: 0,
      failure_class: mismatch ? 'served-model-mismatch' : 'provider-unavailable',
      containment_class: mismatch ? 'output-destroyed-lane-halted' : 'fail-closed-no-fallback',
      mechanism: 'model-turn-coordinator',
      observed_assertions: [
        { name: 'provider_attempt_count', observed: attempts },
        { name: 'durable_failure_reason', observed: call.failure_reason },
        { name: 'quarantine_size', observed: coordinator.quarantine.size },
        { name: 'lane_halted', observed: coordinator.isLaneHalted(context.selectedCard?.card_id ?? '', context.selectedCard?.card_version ?? 1, context.selectedCard?.requested_id ?? '') },
        { name: 'reported_failure_class', observed: failureClass },
      ],
    });
  } finally {
    harness.close();
  }
}

async function executeFullEffect(context: ScenarioContext): Promise<BoundedCaseResult> {
  const harness = await harnessFor(context);
  try {
    await harness.prepareNativeContext();
    const materialInputId = `said_${context.row.id.replaceAll('-', '_')}_${context.laneSlot.replaceAll('-', '_')}`;
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: context.row.id.replaceAll('-', '_'),
      authorization: modelAuthorization(harness),
      lanes: [laneConfig(context, async () => ({
        lane: context.laneSlot === 'lane-0' ? 'publicai' : 'openai',
        requestedId: context.selectedCard?.requested_id ?? '',
        servedId: context.selectedCard?.requested_id ?? '',
        content: nativeProposalContent(materialInputId),
        toolCalls: [],
      }))],
    });
    const proposalRunId = `prun_${context.row.id.replaceAll('-', '_')}_${context.laneSlot.replaceAll('-', '_')}`;
    const frozen = await coordinator.runProposal({
      proposalRunId,
      conversationVersion: harness.store.snapshot().conversationVersionByCase.get(context.row.id.replaceAll('-', '_')) ?? 0,
      turnId: `turn_${context.row.id.replaceAll('-', '_')}_${context.laneSlot.replaceAll('-', '_')}`,
      selectionId: harness.selectionId,
      cardId: context.selectedCard?.card_id ?? '',
      cardVersion: context.selectedCard?.card_version ?? 0,
      requestedId: context.selectedCard?.requested_id ?? '',
    }, { onBehalfOf: { role: 'case_officer', session_id: harness.sessionId } });
    const nativeProposal = harness.store.snapshot().proposals.get(frozen.proposal.proposal_id);
    if (nativeProposal === undefined) throw new Error('native proposal intake lost its frozen proposal');
    const precommit = await harness.proposalPrecommit.run(nativeProposal.proposal_id, ORCHESTRATOR);
    if (precommit.kind !== 'proposal_precommit_status' || precommit.state !== 'verified' || precommit.gates.some((gate) => gate.verdict !== 'allow')) {
      throw new Error('native precommit did not reach verified');
    }
    const preparation = await harness.executionPreparations.issue(
      context.row.id.replaceAll('-', '_'),
      proposalRunId,
      harness.sessionId,
      ORCHESTRATOR,
    );
    const executed = await harness.nativeServices(join(context.recordsRoot, 'services')).executePrepared(
      'w-demo',
      preparation.execution_preparation_id,
    );
    const state = harness.store.snapshot();
    const commit = [...state.rulings.values()].find((ruling) =>
      ruling.gate === 'commit' && ruling.binding.frozen_proposal_hash === nativeProposal.proposal_hash);
    if (executed.state !== 'effect-recorded' || executed.effect_outcome !== 'success' || commit?.verdict !== 'allow' || state.effects.size !== 1) {
      throw new Error('native preparation did not produce exactly one recorded local effect');
    }
    return boundedResult(context, {
      gates: [
        ...precommit.gates.map((gate) => ({ name: gate.gate, verdict: gate.verdict, matched_rule_id: null, ux_class: gate.ux_class })),
        { name: 'commit', verdict: commit.verdict, matched_rule_id: commit.matched_rule_id, ux_class: commit.ux_class },
      ],
      intervention: null,
      commitment_state: 'committed',
      effect_count: state.effects.size,
      failure_class: null,
      containment_class: 'one-local-effect',
      mechanism: 'proposal-intake:precommit:execution-preparation:native-commit-verify:effect-ledger',
      observed_assertions: [
        { name: 'proposal_intake_state', observed: [...state.proposalIntakes.values()][0]?.state ?? null },
        { name: 'precommit_state', observed: precommit.state },
        { name: 'execution_preparation_state', observed: state.executionPreparations.get(preparation.execution_preparation_id)?.state ?? null },
        { name: 'commit_ruling_status', observed: commit.status },
        { name: 'effect_outcome', observed: executed.effect_outcome },
        { name: 'receipt_recorded_at', observed: executed.recorded_at },
      ],
    });
  } finally {
    harness.close();
  }
}

export async function executeBeat(context: ScenarioContext): Promise<BoundedCaseResult> {
  switch (context.row.id) {
    case 'beat-00': {
      const harness = await harnessFor(context);
      try {
        const result = await harness.rule('authorize', harness.proposal());
        if (result.ruling.verdict !== 'allow') throw new Error('bounded mandate did not authorize');
        return successfulResult(context, [result], {
          mechanism: 'authorization-core:mandate-binding',
          observed_assertions: [
            { name: 'declared_purpose_present', observed: harness.mandate.declared_purpose.length > 0 },
            { name: 'limits_present', observed: Object.keys(harness.mandate.limits).length > 0 },
            { name: 'approved_card_bound', observed: harness.mandate.approved_models.some((model) => model.card_digest === context.selectedCard?.card_digest) },
            { name: 'authorized_agent_bound', observed: harness.mandate.authorized_agent.id },
          ],
        });
      } finally { harness.close(); }
    }
    case 'beat-01': {
      const harness = await harnessFor(context, {
        mandateOverrides: { action_class: 'registry-read', connected_service: 'registry', disclosure_destinations: ['registry'] },
      });
      try {
        const result = await harness.rule('submit', harness.proposal({
          exact_parameters: { registry_reference: 'CH-0042' },
          cost_obligation: { amount_minor_units: 0, description: 'No monetary amount.' },
        }));
        if (result.ruling.verdict !== 'allow' || result.ruling.ux_class !== 'silent') throw new Error('registry retrieval was not silently allowed');
        return successfulResult(context, [result], { mechanism: 'policy:allow-registry-read' });
      } finally { harness.close(); }
    }
    case 'beat-02': {
      const harness = await harnessFor(context);
      try {
        const result = await harness.rule('authorize', harness.proposal(), { tool_request_class: 'inadmissible-with-fallback' });
        if (result.ruling.verdict !== 'deny' || result.ruling.ux_class !== 'flag' || result.escalationId !== null) throw new Error('inadmissible tool did not deny without escalation');
        return successfulResult(context, [result], { containment_class: 'fallback-declared-no-escalation', mechanism: 'policy:deny-inadmissible-tool-with-fallback' });
      } finally { harness.close(); }
    }
    case 'beat-03': {
      const harness = await harnessFor(context);
      try {
        harness.setSignals('verify', [signal('evidence_conflict')]);
        const firstProposal = harness.proposal();
        const first = await harness.rule('verify', firstProposal);
        if (first.escalationId === null || first.ruling.verdict !== 'escalate') throw new Error('conflict did not escalate');
        const disposed = await harness.core.disposeEscalation({ escalationId: first.escalationId, disposition: 'narrow-or-modify', actor: CASE_OFFICER });
        if (!disposed.accepted) throw new Error('human narrowing was not accepted');
        harness.setSignals('verify', []);
        const { proposal_hash: ignoredHash, ...firstBody } = firstProposal;
        void ignoredHash;
        const revision = harness.proposal({
          ...firstBody,
          proposal_id: `prp_beat_03_${context.laneSlot.replaceAll('-', '_')}_revision`,
          revision: 2,
          proposed_action: 'File the assessment using only the uncontested synthetic record.',
        });
        const continued = await harness.core.continueEscalationRevision({ escalationId: first.escalationId, proposal: revision, actor: ORCHESTRATOR });
        if (!continued.accepted || continued.stages.some((result) => result.ruling.verdict !== 'allow')) throw new Error('revised proposal did not pass fresh gates');
        const commit = await harness.rule('commit', revision);
        const fresh = [...continued.stages, commit];
        if (commit.ruling.verdict !== 'allow') throw new Error('commit ruling absent');
        const executed = await harness.services(join(context.recordsRoot, 'services')).execute(commit.ruling.ruling_id, harness.intent(revision, commit.ruling.ruling_id));
        if (!executed.ok) throw new Error('narrowed proposal did not reach one local effect');
        return successfulResult(context, [first, ...fresh], {
          intervention: interventionObservation(harness, first.escalationId),
          commitment_state: 'committed', effect_count: 1, containment_class: 'narrowed-revision-one-effect',
          mechanism: 'authorization-core:conflict-disposition-fresh-gates-effect',
          observed_assertions: [
            { name: 'human_narrowing_accepted', observed: disposed.accepted },
            { name: 'fresh_gate_count', observed: fresh.length },
            { name: 'effect_recorded', observed: executed.ok },
          ],
        });
      } finally { harness.close(); }
    }
    case 'beat-04': {
      const harness = await harnessFor(context);
      try {
        const caseId = context.row.id.replaceAll('-', '_');
        await harness.prepareNativeContext();
        const materialInputId = `said_${caseId}_${context.laneSlot.replaceAll('-', '_')}`;
        const freezeDialogueProposal = async (inferenceId: string, suffix: string) => {
          const coordinator = new ModelTurnCoordinator({
            worldId: 'w-demo',
            caseId,
            authorization: modelAuthorization(harness),
            lanes: [laneConfig(context, async () => ({
              lane: context.laneSlot === 'lane-0' ? 'publicai' : 'openai',
              requestedId: context.selectedCard?.requested_id ?? '',
              servedId: context.selectedCard?.requested_id ?? '',
              content: nativeProposalContent(materialInputId, [inferenceId]),
              toolCalls: [],
            }))],
          });
          let frozen;
          try {
            frozen = await coordinator.runProposal({
              proposalRunId: `prun_beat_04_${suffix}_${context.laneSlot.replaceAll('-', '_')}`,
              conversationVersion: harness.store.snapshot().conversationVersionByCase.get(caseId) ?? 0,
              turnId: `turn_beat_04_${suffix}_${context.laneSlot.replaceAll('-', '_')}`,
              selectionId: harness.selectionId,
              cardId: context.selectedCard?.card_id ?? '',
              cardVersion: context.selectedCard?.card_version ?? 0,
              requestedId: context.selectedCard?.requested_id ?? '',
            }, { onBehalfOf: { role: 'case_officer', session_id: harness.sessionId } });
          } catch (error) {
            const intake = [...harness.store.snapshot().proposalIntakes.values()].at(-1);
            throw new Error(`native dialogue proposal failed (${intake?.state ?? 'missing'}:${intake?.refusal_reason ?? 'none'}): ${error instanceof Error ? error.message : String(error)}`);
          }
          const proposal = harness.store.snapshot().proposals.get(frozen.proposal.proposal_id);
          if (proposal === undefined || !proposal.derived_claims.some((item) => item.id === inferenceId)) throw new Error('native dialogue proposal did not bind its inference');
          return proposal;
        };
        const inference = { id: 'inf_synthetic', store: 'inferred' as const, turn: 'turn_1', text: 'Synthetic applicant is at most three years old.', provenance: { derived_from: ['said_synthetic'], hops: [] }, tags: ['conf:case', 'purpose:grant-assessment'] };
        await harness.core.putConversationItems({ caseId, items: [inference], actor: AUTHZ });
        harness.setSignals('verify', [signal('unconfirmed_inference_as_fact', inference.id)]);
        const result = await harness.rule('verify', await freezeDialogueProposal(inference.id, 'correct'));
        if (result.ruling.verdict !== 'escalate' || result.escalationId === null) throw new Error('unconfirmed inference did not open focused dialogue');
        const timeoutInference = { ...inference, id: 'inf_timeout', turn: 'turn_timeout', text: 'Synthetic timeout inference.' };
        await harness.core.putConversationItems({ caseId, items: [timeoutInference], actor: AUTHZ });
        harness.setSignals('verify', [signal('unconfirmed_inference_as_fact', timeoutInference.id)]);
        const timeoutRuling = await harness.rule('verify', await freezeDialogueProposal(timeoutInference.id, 'timeout'));
        if (timeoutRuling.escalationId === null) throw new Error('timeout dialogue did not open');
        const bare = await harness.core.respondDialogue({
          escalationId: result.escalationId,
          disposition: 'confirm',
          scope: { item_ref: inference.id, applies_to: 'this_case_only' },
          actor: CASE_OFFICER,
        });
        if (bare.accepted) throw new Error('bare third-party confirmation was accepted');
        const answerText = 'The synthetic applicant is four years old; the earlier inference is corrected.';
        const corrected = await harness.core.respondDialogue({
          escalationId: result.escalationId,
          disposition: 'correct',
          answerText,
          scope: { item_ref: inference.id, applies_to: 'this_case_only' },
          actor: CASE_OFFICER,
        });
        if (!corrected.accepted) throw new Error(`cited dialogue correction was not recorded (${corrected.defect})`);
        const replay = await harness.core.respondDialogue({
          escalationId: result.escalationId,
          disposition: 'correct',
          answerText,
          scope: { item_ref: inference.id, applies_to: 'this_case_only' },
          actor: CASE_OFFICER,
        });
        if (replay.accepted || replay.defect !== 'late-response') throw new Error('dialogue response was not single-use');
        const projected = await harness.projections().beginCall({
          turn_id: `turn_reproject_${context.laneSlot.replaceAll('-', '_')}`,
          selection_id: harness.selectionId,
          actor: ORCHESTRATOR,
        });
        const projectionItems = projected.projection.items;
        await harness.projections().failCall({
          call_id: projected.call.call_id,
          turn_id: projected.call.turn_id,
          selection_id: projected.call.selection_id,
          served_id: null,
          projection_digest: projected.call.projection_digest,
          provider_disclosure: 'possible',
          failure_reason: 'provider-unavailable',
          actor: ORCHESTRATOR,
        });
        if (projectionItems.some((item) => item.id === inference.id) || !projectionItems.some((item) => item.store === 'said' && item.text === answerText)) {
          throw new Error('dialogue correction did not re-project the bounded conversation');
        }
        harness.setNow('2026-08-01T09:16:00.000Z');
        const timedOut = await harness.core.respondDialogue({ escalationId: timeoutRuling.escalationId, disposition: 'abstain', actor: CASE_OFFICER });
        const timeoutEscalation = harness.store.snapshot().escalations.get(timeoutRuling.escalationId);
        const timeoutRecord = harness.store.snapshot().actionRecords.find((entry) =>
          entry.human_intervention_event?.event === 'human_intervention_event' &&
          entry.human_intervention_event.payload.kind === 'dialogue_timeout' &&
          entry.human_intervention_event.escalation_id === timeoutRuling.escalationId);
        if (timedOut.accepted || timeoutEscalation?.state !== 'timed_out' || timeoutEscalation.terminal_disposition !== 'abstain' || timeoutRecord === undefined) {
          throw new Error('dialogue timeout did not apply and record abstention');
        }
        const responseRecord = harness.store.snapshot().actionRecords.find((entry) => entry.entry_id === corrected.recordEntryId);
        const payload = responseRecord?.human_intervention_event?.event === 'human_intervention_event'
          ? responseRecord.human_intervention_event.payload
          : undefined;
        if (payload?.kind !== 'dialogue_response_recorded' || payload.scope?.item_ref !== inference.id) throw new Error('dialogue response evidence was not bound to the cited item');
        return successfulResult(context, [result], {
          intervention: interventionObservation(harness, result.escalationId),
          commitment_state: 'blocked',
          containment_class: 'dialogue-single-use-corrected-and-timeout-abstained',
          mechanism: 'authorization-core:focused-dialogue-response-and-timeout',
          observed_assertions: [
            { name: 'signal_present_in_evidence', observed: result.ruling.evidence_refs.some((ref) => ref.kind === 'screening_signal' && ref.signal === 'unconfirmed_inference_as_fact') },
            { name: 'dialogue_item_ref', observed: harness.store.snapshot().escalations.get(result.escalationId)?.dialogue_item_ref ?? null },
            { name: 'bare_confirmation_defect', observed: bare.accepted ? null : bare.defect },
            { name: 'correction_recorded', observed: corrected.accepted },
            { name: 'response_replay_defect', observed: replay.accepted ? null : replay.defect },
            { name: 'reprojected_answer_present', observed: projectionItems.some((item) => item.store === 'said' && item.text === answerText) },
            { name: 'timeout_default', observed: timeoutEscalation?.terminal_disposition ?? null },
            { name: 'timeout_recorded', observed: timeoutRecord !== undefined },
            { name: 'no_effect', observed: harness.store.snapshot().effects.size },
          ],
        });
      } finally { harness.close(); }
    }
    case 'beat-05': {
      const harness = await harnessFor(context);
      try {
        harness.setSignals('submit', [signal('injection_suspicion')]);
        const result = await harness.rule('submit', harness.proposal());
        if (result.ruling.verdict !== 'escalate' || result.ruling.ux_class !== 'stop') throw new Error('injection signal did not stop');
        return successfulResult(context, [result], { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', containment_class: 'signal-stop-no-allow', mechanism: 'policy:escalate-submit-signal' });
      } finally { harness.close(); }
    }
    case 'beat-06': return executeFullEffect(context);
    case 'beat-07':
    case 'beat-17': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const ruled = await harness.rule('commit', proposal);
        if (ruled.ruling.verdict !== 'allow') throw new Error('baseline commitment ruling was not allowed');
        const intent = harness.intent(proposal, ruled.ruling.ruling_id, { exact_parameters: { ...proposal.exact_parameters, amount_minor_units: 10001 } });
        const executed = await harness.services(join(context.recordsRoot, 'services')).execute(ruled.ruling.ruling_id, intent);
        if (executed.ok || executed.stage !== 'commit-verify' || executed.defect !== 'proposal-mismatch') throw new Error('above-envelope execution was not blocked by exact binding');
        return successfulResult(context, [ruled], { commitment_state: 'blocked', failure_class: 'proposal-mismatch', containment_class: 'executing-service-blocked', mechanism: 'authorization-core:commit-verify-exact-intent', observed_assertions: [{ name: 'effect_count', observed: harness.store.snapshot().effects.size }, { name: 'service_stage', observed: executed.stage }, { name: 'defect', observed: executed.defect }] });
      } finally { harness.close(); }
    }
    case 'beat-08': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const ruled = await harness.rule('commit', proposal);
        const intent = harness.intent(proposal, ruled.ruling.ruling_id);
        const ledgerRoot = join(context.recordsRoot, 'services');
        const first = await harness.services(ledgerRoot).execute(ruled.ruling.ruling_id, intent);
        const replay = await harness.services(ledgerRoot).execute(ruled.ruling.ruling_id, intent);
        if (!first.ok || replay.ok || replay.stage !== 'commit-verify' || replay.defect !== 'replayed-ruling') throw new Error('ruling replay did not fail closed');
        return successfulResult(context, [ruled], { commitment_state: 'already_bound', effect_count: 1, failure_class: 'replayed-ruling', containment_class: 'single-effect-replay-refused', mechanism: 'authorization-core:nonce-replay', observed_assertions: [{ name: 'first_effect', observed: first.ok }, { name: 'replay_refused', observed: !replay.ok }, { name: 'durable_effect_count', observed: harness.store.snapshot().effects.size }] });
      } finally { harness.close(); }
    }
    case 'beat-09': {
      const harness = await harnessFor(context, { now: '2026-08-02T00:00:00.001Z' });
      try {
        const result = await harness.rule('authorize', harness.proposal());
        if (result.ruling.verdict !== 'deny' || result.ruling.matched_rule_id !== 'authority:expired-mandate') throw new Error('expired mandate did not deny');
        return successfulResult(context, [result], { commitment_state: 'blocked', failure_class: 'expired-mandate', containment_class: 'fail-closed', mechanism: 'authorization-core:mandate-currentness' });
      } finally { harness.close(); }
    }
    case 'beat-10': {
      const harness = await harnessFor(context);
      try {
        const result = await harness.rule('authorize', harness.proposal(), { tool_request_class: 'new-tool-privilege-recipient-purpose' });
        if (result.ruling.verdict !== 'escalate' || result.escalationId === null) throw new Error('new privilege did not escalate');
        return successfulResult(context, [result], { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', containment_class: 'principal-route-no-authority', mechanism: 'policy:escalate-new-authority', observed_assertions: [{ name: 'eligible_role', observed: harness.store.snapshot().escalations.get(result.escalationId)?.contract.decision_and_route.eligible_role ?? null }, { name: 'commitment_count', observed: harness.store.snapshot().commitments.size }] });
      } finally { harness.close(); }
    }
    case 'beat-11': {
      const harness = await harnessFor(context);
      try {
        const result = await harness.rule('authorize', harness.proposal(), { tool_request_class: 'new-tool-privilege-recipient-purpose' });
        if (result.escalationId === null) throw new Error('timeout fixture did not escalate');
        harness.setNow('2026-08-01T09:16:00.000Z');
        const contract = harness.store.snapshot().escalations.get(result.escalationId)?.contract;
        const declaredDefault = contract?.response_bound_and_default.safe_default;
        if (declaredDefault?.kind !== 'stop-remains' || declaredDefault.disposition !== 'cancel' || !declaredDefault.reversible || declaredDefault.authority_basis.kind !== 'no-new-authority') {
          throw new Error('timeout fixture did not declare a reversible no-new-authority fallback');
        }
        const late = await harness.core.disposeEscalation({ escalationId: result.escalationId, disposition: 'allow-within-scope', actor: PRINCIPAL });
        const escalation = harness.store.snapshot().escalations.get(result.escalationId);
        const timeoutRecord = harness.store.snapshot().actionRecords.find((entry) =>
          entry.human_intervention_event?.event === 'human_intervention_event' &&
          entry.human_intervention_event.payload.kind === 'escalation_timeout' &&
          entry.human_intervention_event.escalation_id === result.escalationId);
        const timeoutPayload = timeoutRecord?.human_intervention_event?.event === 'human_intervention_event'
          ? timeoutRecord.human_intervention_event.payload
          : undefined;
        if (late.accepted || escalation?.state !== 'timed_out' || escalation.terminal_disposition !== 'cancel' || timeoutPayload?.kind !== 'escalation_timeout' || timeoutPayload.applied_default !== 'cancel') {
          throw new Error('late approval did not leave the declared Stop fallback in force');
        }
        return successfulResult(context, [result], { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', failure_class: 'late-disposition', containment_class: 'timeout-stop-remains', mechanism: 'authorization-core:escalation-timeout', observed_assertions: [{ name: 'declared_default', observed: declaredDefault.disposition }, { name: 'default_reversible', observed: declaredDefault.reversible }, { name: 'default_authority_basis', observed: declaredDefault.authority_basis.kind }, { name: 'applied_default', observed: timeoutPayload.applied_default }, { name: 'late_allow_accepted', observed: late.accepted }, { name: 'terminal_state', observed: escalation.state }, { name: 'commitment_count', observed: harness.store.snapshot().commitments.size }] });
      } finally { harness.close(); }
    }
    case 'beat-12': {
      const harness = await harnessFor(context, { mandateOverrides: { action_class: 'notification', connected_service: 'notification', disclosure_destinations: ['notification'] } });
      try {
        const results: RuleProposalResult[] = [];
        for (let index = 0; index < 3; index += 1) {
          const proposal = harness.proposal({ exact_parameters: { notification_volume: 6, reference: `pattern-${index + 1}` }, cost_obligation: { amount_minor_units: 0, description: 'No monetary amount.' } });
          results.push(await harness.core.ruleProposal({ gate: 'commit', proposal, service: 'notification', actionClass: 'notification', actor: ORCHESTRATOR }));
        }
        const result = results.at(-1)!;
        const state = harness.store.snapshot();
        const mandateStatus = state.mandateStatus.get(harness.mandate.mandate_id);
        const amended = mandateStatus === undefined ? undefined : state.mandates.get(`${harness.mandate.mandate_id}@${mandateStatus.version}`);
        if (results.some((candidate) => candidate.ruling.verdict !== 'escalate') || state.patternEvents.length !== 3 || !result.mandateNarrowed || mandateStatus?.state !== 'suspended' || amended?.state !== 'suspended') {
          throw new Error('three-event aggregate pattern did not narrow the mandate pending re-authorization');
        }
        return successfulResult(context, results, { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', containment_class: 'narrowed-pending-reauthorization', mechanism: 'authorization-core:aggregate-counter-pattern', observed_assertions: [{ name: 'pattern_event_count', observed: state.patternEvents.length }, { name: 'matched_rule', observed: result.ruling.matched_rule_id }, { name: 'mandate_narrowed', observed: result.mandateNarrowed }, { name: 'amended_mandate_state', observed: amended?.state ?? null }] });
      } finally { harness.close(); }
    }
    case 'beat-13': {
      const harness = await harnessFor(context);
      try {
        const result = await harness.rule('authorize', harness.proposal(), { tool_request_class: 'new-tool-privilege-recipient-purpose' });
        if (result.escalationId === null) throw new Error('cancel fixture did not escalate');
        const disposed = await harness.core.disposeEscalation({ escalationId: result.escalationId, disposition: 'cancel', actor: PRINCIPAL });
        if (!disposed.accepted || harness.store.snapshot().effects.size !== 0) throw new Error('precommit cancel was not effect-free');
        return successfulResult(context, [result], { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', containment_class: 'precommit-cancel-no-effect', mechanism: 'authorization-core:intervention-cancel', observed_assertions: [{ name: 'cancel_accepted', observed: disposed.accepted }, { name: 'effect_count', observed: harness.store.snapshot().effects.size }, { name: 'recovery_owner_role', observed: 'principal' }] });
      } finally { harness.close(); }
    }
    case 'beat-14': return executeModelFailure(context, false);
    case 'beat-15': {
      const harness = await harnessFor(context);
      try {
        await harness.rule('authorize', harness.proposal({ action_id: 'act_beat_15_one' }));
        await harness.rule('authorize', harness.proposal({ action_id: 'act_beat_15_two' }));
        const checkpointsRoot = join(context.stagingRoot, 'checkpoint-artifacts', context.row.id, context.laneSlot);
        mkdirSync(checkpointsRoot, { recursive: true });
        const checkpoint = await writeCheckpoint({
          recordsRoot: context.recordsRoot,
          checkpointsRoot,
          reason: 'M6 beat 15 deterministic local verification',
          runId: `checkpoint_${context.row.id.replaceAll('-', '_')}_${context.laneSlot.replaceAll('-', '_')}`,
          policyContentDigest: harness.policy.policyContentDigest,
          evaluatorBuildId: harness.policy.evaluatorBuildId,
          now: () => context.fixedNow,
          mode: 'write-only',
        });
        const actionFile = join(context.recordsRoot, 'w-demo', 'action.jsonl');
        const clean = readFileSync(actionFile, 'utf8');
        const expectVerificationCode = async (expected: 'chain-tamper' | 'rollback'): Promise<string> => {
          try {
            await verifyRecords({ recordsRoot: context.recordsRoot, checkpointsRoot, worldId: 'w-demo', local: true, now: () => context.fixedNow });
          } catch (error) {
            if (error instanceof RecordVerificationError && error.code === expected) return error.code;
            throw error;
          }
          throw new Error(`record verification did not raise ${expected}`);
        };
        const tamperedBytes = clean.replace('"world_id":"w-demo"', '"world_id":"w-Xemo"');
        if (tamperedBytes === clean) throw new Error('action record fixture had no bounded tamper target');
        writeFileSync(actionFile, tamperedBytes, 'utf8');
        const tamperCode = await expectVerificationCode('chain-tamper');
        writeFileSync(actionFile, clean, 'utf8');
        const cleanLines = clean.trimEnd().split('\n');
        writeFileSync(actionFile, `${cleanLines.slice(0, -1).join('\n')}\n`, 'utf8');
        const rollbackCode = await expectVerificationCode('rollback');
        writeFileSync(actionFile, clean, 'utf8');
        const verified = await verifyRecords({
          recordsRoot: context.recordsRoot,
          checkpointsRoot,
          worldId: 'w-demo',
          local: true,
          now: () => context.fixedNow,
          recordVerification: (readLengths) => recordVerificationAccess(harness.store, readLengths),
        });
        const verificationAccess = harness.store.snapshot().accessRecords.find((entry) => 'route' in entry && entry.route === 'VERIFY records');
        const actionHead = checkpoint.streams.find((head) => head.world === 'w-demo' && head.stream === 'action');
        if (verified.checkpoint?.checkpoint_id !== checkpoint.checkpoint_id || verificationAccess === undefined || actionHead === undefined) {
          throw new Error('local verification did not bind and record the checkpoint head');
        }
        return boundedResult(context, { gates: [], intervention: null, commitment_state: 'none', effect_count: 0, failure_class: 'record-divergence', containment_class: 'tamper-and-rollback-halt-against-checkpoint-head', mechanism: 'checkpoint:local-verify:verification-access', observed_assertions: [{ name: 'inline_tamper_error', observed: tamperCode }, { name: 'valid_prefix_error', observed: rollbackCode }, { name: 'checkpoint_id', observed: checkpoint.checkpoint_id }, { name: 'bound_action_length', observed: actionHead.length }, { name: 'verification_access_route', observed: 'route' in verificationAccess ? verificationAccess.route : null }] });
      } finally { harness.close(); }
    }
    case 'beat-16': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const result = await harness.rule('rely', proposal);
        const checkpointsRoot = join(context.stagingRoot, 'readside-checkpoints', context.row.id, context.laneSlot);
        mkdirSync(checkpointsRoot, { recursive: true });
        const readSide = new AuthorizationReadSide({
          store: harness.store,
          cards: harness.cards,
          recordsRoot: context.recordsRoot,
          worldId: 'w-demo',
          verifyRecordLayer: () => verifyRecords({ recordsRoot: context.recordsRoot, checkpointsRoot, worldId: 'w-demo', local: true, now: () => context.fixedNow }),
        });
        const projected = await readSide.applicantExtract(APPLICANT);
        const extract = projected.body;
        const encoded = JSON.stringify(extract);
        if (extract.scope.role !== 'applicant' || extract.actions.length !== 1 || extract.actions[0]?.proposal_id !== proposal.proposal_id || encoded.includes('exact_parameters') || encoded.includes('binding') || encoded.includes('replay_protection')) throw new Error('role-scoped applicant projection leaked or lost bounded evidence');
        return successfulResult(context, [result], { containment_class: 'scoped-applicant-projection-local-receipt', mechanism: 'authorization-read-side:applicant-extract', observed_assertions: [{ name: 'projected_role', observed: extract.scope.role }, { name: 'projected_action_count', observed: extract.actions.length }, { name: 'local_receipt_honesty', observed: extract.receipt.notice }, { name: 'latest_pushed_checkpoint_absent', observed: extract.receipt.latest_pushed_checkpoint === null }, { name: 'raw_binding_excluded', observed: !encoded.includes('binding') }, { name: 'verified_action_read_length', observed: projected.readLengths['w-demo/action'] ?? null }] });
      } finally { harness.close(); }
    }
    case 'beat-18': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal({ action_id: 'act_beat_18' });
        const ruled = await harness.rule('authorize', proposal);
        const challenged = await harness.core.submitChallenge({ actionId: proposal.action_id, contestedEntryId: ruled.recordEntryId, correctionText: 'Synthetic factual correction.', actor: APPLICANT });
        if (!challenged.accepted) throw new Error('factual correction did not open review');
        const record = harness.store.snapshot().actionRecords.find((entry) => entry.entry_id === challenged.recordEntryId);
        return successfulResult(context, [ruled], { containment_class: 'reliance-withdrawn-pending-review', mechanism: 'authorization-core:challenge-remedy', observed_assertions: [{ name: 'challenge_accepted', observed: challenged.accepted }, { name: 'reliance_state', observed: record?.challenge_and_remedy?.reliance_state ?? null }, { name: 'review_obligation_open', observed: harness.store.snapshot().reviews.size }] });
      } finally { harness.close(); }
    }
    case 'beat-19': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const old = await harness.rule('submit', proposal);
        const other = harness.mandate.approved_models.find((entry) => entry.card_id !== context.selectedCard?.card_id && entry.roles.includes('acting'));
        if (other === undefined) throw new Error('second approved acting card absent');
        const projections = harness.projections();
        const checked = await projections.checkSelection({ expected_current_selection_id: harness.selectionId, target: { card_id: other.card_id, card_version: other.card_version, requested_id: other.requested_id }, actor: ORCHESTRATOR });
        const switched = await projections.selectModel({ check_id: checked.check.check_id, expected_current_selection_id: harness.selectionId, actor: ORCHESTRATOR });
        if (switched.selection.kind !== 'switch' || harness.store.snapshot().rulings.get(old.ruling.ruling_id)?.status !== 'invalidated') throw new Error('model switch did not invalidate prior gate state');
        const otherInspection = harness.cards.get(other.card_id);
        if (otherInspection === undefined) throw new Error('switched card inspection absent');
        const lane = other.requested_id === 'gpt-5.5' ? 'openai' as const : 'publicai' as const;
        const coordinator = new ModelTurnCoordinator({
          worldId: 'w-demo',
          caseId: context.row.id.replaceAll('-', '_'),
          authorization: modelAuthorization(harness),
          lanes: [{
            lane,
            cardId: other.card_id,
            cardVersion: other.card_version,
            requestedId: other.requested_id,
            adapter: { lane, requestedId: other.requested_id, act: async () => ({ lane, requestedId: other.requested_id, servedId: other.requested_id, content: 'Synthetic post-switch turn.', toolCalls: [] }) },
          }],
        });
        const turn = await coordinator.run({
          turnId: `turn_switch_${context.laneSlot.replaceAll('-', '_')}`,
          selectionId: switched.selection.selection_id,
          cardId: other.card_id,
          cardVersion: other.card_version,
          requestedId: other.requested_id,
          maxOutputTokens: 64,
        });
        if (turn.disposition !== 'quarantined') throw new Error('post-switch turn was not admitted into quarantine');
        const { proposal_hash: ignoredHash, ...proposalBody } = harness.proposal();
        void ignoredHash;
        const switchedProposal = freezeProposal({
          ...proposalBody,
          proposal_id: `prp_beat_19_switched_${context.laneSlot.replaceAll('-', '_')}`,
          selection_id: switched.selection.selection_id,
          acting_model: { requested_id: other.requested_id, served_id: other.requested_id, card_id: other.card_id, card_version: other.card_version },
        });
        const submit = await harness.rule('submit', switchedProposal);
        const verify = await harness.rule('verify', switchedProposal);
        const call = harness.store.snapshot().modelCalls.get(turn.quarantine.call_id);
        if (submit.ruling.verdict !== 'allow' || verify.ruling.verdict !== 'allow' || call?.served_id !== other.requested_id) {
          throw new Error('switch did not re-arm Submit/Verify and record the served identity');
        }
        return successfulResult(context, [old, submit, verify], { containment_class: 'selection-switched-gates-rearmed', mechanism: 'conversation-projection:model-selection-switch-and-turn', observed_assertions: [{ name: 'card_shown', observed: checked.evidence.current_card !== null }, { name: 'invalidated_ruling_count', observed: switched.invalidated_ruling_count }, { name: 'requested_id', observed: switched.selection.target.requested_id }, { name: 'served_id_recorded', observed: call?.served_id ?? null }, { name: 'rearmed_submit', observed: submit.ruling.verdict }, { name: 'rearmed_verify', observed: verify.ruling.verdict }] });
      } finally { harness.close(); }
    }
    case 'beat-20': {
      if (context.laneSlot === 'lane-0') {
        const harness = await harnessFor(context);
        try {
          const result = await harness.rule('submit', harness.proposal());
          if (result.ruling.verdict !== 'allow') throw new Error('approved provider fixture did not allow');
          return successfulResult(context, [result], { containment_class: 'continued', mechanism: 'authorization-core:provider-permission-fixture', observed_assertions: [{ name: 'mandate_permission', observed: 'approved' }, { name: 'disclosure_boundary', observed: 'permitted' }] });
        } finally { harness.close(); }
      }
      const mandateBody = JSON.parse(readFileSync(join(REPOSITORY_ROOT, 'fixtures', 'demo', 'mandate.json'), 'utf8')) as Omit<Mandate, 'binding'>;
      const approvedModels = mandateBody.approved_models.filter((entry) =>
        entry.card_id !== context.selectedCard?.card_id || entry.card_version !== context.selectedCard.card_version);
      const defaultActingModel = approvedModels.find((entry) => entry.roles.includes('acting'));
      if (defaultActingModel === undefined) throw new Error('beat-20 exclusion lost the remaining approved acting model');
      const harness = await harnessFor(context, {
        mandateOverrides: {
          approved_models: approvedModels,
          default_acting_model: {
            card_id: defaultActingModel.card_id,
            card_version: defaultActingModel.card_version,
            requested_id: defaultActingModel.requested_id,
          },
        },
      });
      try {
        const proposal = harness.proposal();
        const ruled = await harness.rule('submit', proposal);
        const permission = harness.mandate.approved_models.some((entry) => entry.card_id === context.selectedCard?.card_id && entry.card_version === context.selectedCard.card_version && entry.requested_id === context.selectedCard.requested_id && entry.roles.includes('acting'));
        const derivedModelDefect = ruled.ruling.matched_rule_id === 'authority:substituted-model' || ruled.ruling.matched_rule_id === 'authority:stale-selection';
        if (permission || ruled.ruling.verdict !== 'deny' || !derivedModelDefect) throw new Error(`core did not derive an unapproved-model denial from the bound mandate (${permission}:${ruled.ruling.verdict}:${ruled.ruling.matched_rule_id})`);
        return boundedResult(context, {
          gates: [gateObservation(ruled)],
          intervention: null, commitment_state: 'blocked', effect_count: 0, failure_class: 'substituted-model',
          containment_class: 'stopped-before-disclosure', mechanism: 'authorization-core:mandate-derived-model-defect',
          observed_assertions: [{ name: 'mandate_permission', observed: permission ? 'approved' : 'unapproved' }, { name: 'matched_rule', observed: ruled.ruling.matched_rule_id }, { name: 'disclosure_boundary', observed: 'blocked_before_disclosure' }, { name: 'durable_effect_count', observed: harness.store.snapshot().effects.size }],
        });
      } finally { harness.close(); }
    }
    case 'beat-21': {
      const pure = compareServedId(context.selectedCard?.requested_id, context.laneSlot === 'lane-0' ? 'exact-match-required' : 'alias-to-dated-snapshot', 'synthetic-unapproved-model');
      if (pure !== 'mismatch') throw new Error('served-id comparator did not detect mismatch');
      return executeModelFailure(context, true);
    }
    default: throw new Error(`unknown beat executor ${context.row.id}`);
  }
}
