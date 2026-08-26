// SPDX-License-Identifier: MIT
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  appendEntry,
  applicantExtractProjection,
  compareServedId,
  evaluatePolicy,
  type FrozenProposal,
  type RuleProposalResult,
  type ScreeningSignal,
  verifyChain,
} from 'gate-core/offline-safe';
import { ModelAdapterError } from 'model-adapters/offline-safe';
import { ModelTurnCoordinator, type ModelTurnAuthorizationClient, type ModelTurnLaneConfig } from 'runtime-consoles/offline-safe';

import { ProductionHarness, type ProductionHarnessOptions } from './productionHarness.js';
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
    beginModelCall: async (input) => projections.beginCall({
      turn_id: input.turnId,
      selection_id: input.selectionId,
      ingress_binding: input.ingressBinding ?? null,
      proposal_binding: input.proposalBinding ?? null,
      revision_binding: input.revisionBinding ?? null,
      actor: ORCHESTRATOR,
    }),
    admitModelOutput: async (_world, callId, input) => projections.completeCall({ call_id: callId, output: input, actor: ORCHESTRATOR }),
    failModelCall: async (_world, input) => projections.failCall({ ...input, actor: ORCHESTRATOR }),
  };
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
      containment_class: mismatch ? 'quarantined-lane-halted' : 'fail-closed-no-fallback',
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
    const proposal = harness.proposal();
    const gates: RuleProposalResult[] = [];
    for (const gate of ['authorize', 'submit', 'verify', 'commit'] as const) gates.push(await harness.rule(gate, proposal));
    if (gates.some((result) => result.ruling.verdict !== 'allow')) throw new Error('fresh gate sequence did not allow');
    const commit = gates.at(-1);
    if (commit === undefined) throw new Error('commit ruling absent');
    const services = harness.services(join(context.recordsRoot, 'services'));
    const executed = await services.execute(commit.ruling.ruling_id, harness.intent(proposal, commit.ruling.ruling_id));
    if (!executed.ok || executed.delivery !== 'executed') throw new Error('local mock effect did not execute');
    return successfulResult(context, gates, {
      commitment_state: 'committed',
      effect_count: 1,
      containment_class: 'one-local-effect',
      mechanism: 'authorization-core:commit-verify:effect-ledger',
      observed_assertions: [
        { name: 'effect_recorded', observed: executed.report.accepted },
        { name: 'delivery', observed: executed.delivery },
        { name: 'effect_outcome', observed: executed.effect.outcome },
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
        harness.setSignals('verify', [signal('unconfirmed_inference_as_fact', 'inf_synthetic')]);
        const result = await harness.rule('verify', harness.proposal({
          derived_claims: [{ id: 'inf_synthetic', store: 'inferred', turn: 'turn_1', text: 'Synthetic applicant is at most three years old.', provenance: { derived_from: ['said_synthetic'], hops: [] }, tags: ['conf:case', 'purpose:grant-assessment'] }],
        }));
        if (result.ruling.verdict !== 'escalate') throw new Error('unconfirmed inference did not stop');
        return successfulResult(context, [result], {
          intervention: interventionObservation(harness, result.escalationId),
          commitment_state: 'blocked',
          containment_class: 'dialogue-scope-fails-closed-without-native-origin',
          mechanism: 'authorization-core:unconfirmed-inference-dialogue-guard',
          observed_assertions: [
            { name: 'signal_present_in_evidence', observed: result.ruling.evidence_refs.some((ref) => ref.kind === 'screening_signal' && ref.signal === 'unconfirmed_inference_as_fact') },
            { name: 'dialogue_item_ref_absent_without_native_origin', observed: result.escalationId === null ? null : harness.store.snapshot().escalations.get(result.escalationId)?.dialogue_item_ref === null },
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
        const late = await harness.core.disposeEscalation({ escalationId: result.escalationId, disposition: 'deny', actor: PRINCIPAL });
        const escalation = harness.store.snapshot().escalations.get(result.escalationId);
        if (late.accepted || escalation?.state !== 'timed_out') throw new Error('late approval did not remain a no-op');
        return successfulResult(context, [result], { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', failure_class: 'late-disposition', containment_class: 'timeout-stop-remains', mechanism: 'authorization-core:escalation-timeout', observed_assertions: [{ name: 'late_accepted', observed: late.accepted }, { name: 'terminal_state', observed: escalation?.state ?? null }, { name: 'commitment_count', observed: harness.store.snapshot().commitments.size }] });
      } finally { harness.close(); }
    }
    case 'beat-12': {
      const harness = await harnessFor(context, { mandateOverrides: { action_class: 'notification', connected_service: 'notification', disclosure_destinations: ['notification'] } });
      try {
        const proposal = harness.proposal({ exact_parameters: { notification_volume: 6 }, cost_obligation: { amount_minor_units: 0, description: 'No monetary amount.' } });
        const result = await harness.core.ruleProposal({ gate: 'commit', proposal, service: 'notification', actionClass: 'notification', actor: ORCHESTRATOR });
        if (result.ruling.verdict !== 'escalate') throw new Error('aggregate ceiling did not escalate');
        return successfulResult(context, [result], { intervention: interventionObservation(harness, result.escalationId), commitment_state: 'blocked', containment_class: result.mandateNarrowed ? 'narrowed-pending-reauthorization' : 'aggregate-stop', mechanism: 'authorization-core:aggregate-counter', observed_assertions: [{ name: 'matched_rule', observed: result.ruling.matched_rule_id }, { name: 'mandate_narrowed', observed: result.mandateNarrowed }] });
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
      const file = join(context.recordsRoot, 'tamper-chain.jsonl');
      appendEntry(file, 'record-entry', { event: 'synthetic-one' });
      appendEntry(file, 'record-entry', { event: 'synthetic-two' });
      const clean = readFileSync(file, 'utf8');
      writeFileSync(file, clean.replace('synthetic-one', 'synthetic-Xne'), 'utf8');
      const tampered = verifyChain(file, 'record-entry');
      writeFileSync(file, clean.split('\n').slice(0, 1).join('\n') + '\n', 'utf8');
      const prefix = verifyChain(file, 'record-entry');
      if (tampered.ok || !prefix.ok || prefix.length !== 1) throw new Error('chain tamper fixture did not distinguish tamper from valid prefix');
      return boundedResult(context, { gates: [], intervention: null, commitment_state: 'none', effect_count: 0, failure_class: 'record-divergence', containment_class: 'tamper-and-prefix-detected-against-bound-head', mechanism: 'record-chain:verify', observed_assertions: [{ name: 'inline_tamper_detected', observed: !tampered.ok }, { name: 'valid_prefix_length', observed: prefix.ok ? prefix.length : -1 }, { name: 'bound_original_length', observed: 2 }] });
    }
    case 'beat-16': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const result = await harness.rule('rely', proposal);
        const entry = harness.store.snapshot().actionRecords.find((candidate) => candidate.entry_id === result.recordEntryId);
        if (entry === undefined) throw new Error('applicant projection fixture lost its action record');
        const extract = applicantExtractProjection.parse({
          world_id: proposal.world_id,
          scope: { role: 'applicant', resources: [proposal.target.resource] },
          actions: [{
            action_id: proposal.action_id, proposal_id: proposal.proposal_id, revision: proposal.revision,
            declared_objective: proposal.declared_objective, proposed_action: proposal.proposed_action, target: proposal.target,
            material_consequences: proposal.material_consequences,
            authority: { mandate_id: harness.mandate.mandate_id, mandate_version: harness.mandate.version },
            system_use_decision: result.ruling.binding.system_use_decision,
            system_use_current_at_record: entry.system_use_current_at_record,
            ruling: { ruling_id: result.ruling.ruling_id, verdict: result.ruling.verdict, reason: result.ruling.reason, status: result.ruling.status },
            effects: [], interventions: [], challenge_and_remedy: null,
          }],
          receipt: {
            kind: 'local-record-receipt',
            notice: 'A true lodgment receipt requires independent custody, which this POC does not provide.',
            latest_pushed_checkpoint: null,
            action_entries: [{ entry_id: entry.entry_id, action_id: proposal.action_id, index: 0, inside_anchored_prefix: false, system_use_decision: entry.system_use_decision, system_use_current_at_record: entry.system_use_current_at_record }],
            open_window: { entries: 1, minutes: 0 },
          },
        });
        const encoded = JSON.stringify(extract);
        if (encoded.includes('exact_parameters') || encoded.includes('binding') || encoded.includes('replay_protection')) throw new Error('applicant projection leaked internal authority fields');
        return successfulResult(context, [result], { containment_class: 'scoped-applicant-projection-local-receipt', mechanism: 'authorization-projection:applicant-extract-schema', observed_assertions: [{ name: 'projected_action_count', observed: extract.actions.length }, { name: 'local_receipt_honesty', observed: extract.receipt.notice }, { name: 'latest_pushed_checkpoint_absent', observed: extract.receipt.latest_pushed_checkpoint === null }, { name: 'raw_binding_excluded', observed: !encoded.includes('binding') }] });
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
        return successfulResult(context, [old], { containment_class: 'selection-switched-gates-rearmed', mechanism: 'conversation-projection:model-selection-switch', observed_assertions: [{ name: 'card_shown', observed: checked.evidence.current_card !== null }, { name: 'invalidated_ruling_count', observed: switched.invalidated_ruling_count }, { name: 'requested_id', observed: switched.selection.target.requested_id }, { name: 'served_id_recorded_later', observed: true }] });
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
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const evaluated = evaluatePolicy(harness.policy.policy, {
          gate: 'submit', proposal, mandate: harness.mandate, context: {}, counters: {}, signals: [],
          screeningPerformed: false, patternEvents: [], now: harness.now, authorityDefects: ['substituted-model'],
        });
        if (evaluated.verdict !== 'deny' || evaluated.matchedRuleId !== 'authority:substituted-model') throw new Error('unapproved model did not deny before disclosure');
        return boundedResult(context, {
          gates: [{ name: 'submit', verdict: evaluated.verdict, matched_rule_id: evaluated.matchedRuleId, ux_class: evaluated.uxClass }],
          intervention: null, commitment_state: 'blocked', effect_count: 0, failure_class: 'substituted-model',
          containment_class: 'stopped-before-disclosure', mechanism: 'policy-evaluator:authority-defect',
          observed_assertions: [{ name: 'mandate_permission', observed: 'unapproved' }, { name: 'disclosure_boundary', observed: 'blocked_before_disclosure' }, { name: 'durable_effect_count', observed: harness.store.snapshot().effects.size }],
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
