// SPDX-License-Identifier: MIT
import { join } from 'node:path';

import {
  applyWorldOp,
  AuthorizationHttpAdapter,
  bindMandate,
  canonicalize,
  CaseSessionHandoffError,
  CaseSessionHandoffService,
  commitToken,
  createEmbeddedMac,
  createWorldState,
  digestFor,
  freezeProposal,
  loadPolicyFile,
  sha256Hex,
  type CommitToken,
  type DisposeEscalationResult,
  type EffectIntent,
  type Mandate,
  type RuleProposalResult,
  type ScreeningSignal,
  type TransactionActor,
} from 'gate-core/offline-safe';
import {
  ModelTurnCoordinator,
  type ModelTurnAuthorizationClient,
  type ModelTurnLaneConfig,
} from 'runtime-consoles/offline-safe';
import { EffectLedger } from 'services-mock/offline-safe';

import { ProductionHarness, type ProductionHarnessOptions } from './productionHarness.js';
import { REPOSITORY_ROOT } from './repository.js';
import { boundedResult, gateObservation, interventionObservation } from './result.js';
import type { BoundedCaseResult, ScenarioContext } from './types.js';

const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: null } as const;
const SERVICES_HOST = { credential: 'proc:services_host', claimed_role: null } as const;
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const CASE_OFFICER = { credential: 'role:case_officer', claimed_role: 'case_officer' } as const;
const APPLICANT = { credential: 'role:applicant', claimed_role: 'applicant' } as const;
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;
const POLICY_PATH = join(REPOSITORY_ROOT, 'packages', 'gate-core', 'policy', 'v1.yaml');

function signal(kind: ScreeningSignal['signal']): ScreeningSignal {
  return {
    kind: 'screening_signal', signal: kind, confidence_pct: 100,
    rationale: `Synthetic adversarial ${kind} fixture.`, model_id: 'screening-model', model_version_reported: 'screening-model-v1',
  };
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

function nativeProposalContent(materialInputId: string): string {
  return JSON.stringify({
    declared_objective: 'File the synthetic grant application.',
    proposed_action: 'Submit the synthetic grant filing.',
    target: { recipient: 'grant-office', resource: 'application-42' },
    exact_parameters: { amount_minor_units: 50, reference: 'm6-native-recovery' },
    material_input_ids: [materialInputId],
    derived_claim_ids: [],
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

async function harnessFor(
  context: ScenarioContext,
  options: Partial<Omit<ProductionHarnessOptions, 'recordsRoot' | 'caseId' | 'laneSlot' | 'selectedCard'>> = {},
): Promise<ProductionHarness> {
  if (context.laneSlot === 'single' || context.selectedCard === null) throw new Error('adversarial executor requires a lane');
  return ProductionHarness.create({ recordsRoot: context.recordsRoot, caseId: context.row.id, laneSlot: context.laneSlot, selectedCard: context.selectedCard, ...options });
}

function failureResult(
  context: ScenarioContext,
  failureClass: string,
  mechanism: string,
  assertions: BoundedCaseResult['observed_assertions'],
  gates: readonly RuleProposalResult[] = [],
  commitmentState: BoundedCaseResult['commitment_state'] = 'blocked',
  effectCount = 0,
): BoundedCaseResult {
  return boundedResult(context, {
    gates: gates.map(gateObservation), intervention: null, commitment_state: commitmentState,
    effect_count: effectCount, failure_class: failureClass, containment_class: 'fail-closed', mechanism,
    observed_assertions: assertions,
  });
}

function mintToken(harness: ProductionHarness, intent: EffectIntent): CommitToken {
  const body = {
    world_id: intent.world_id,
    effect_id: 'eff_m6_token_fixture',
    ruling_id: intent.ruling_id,
    frozen_proposal_hash: intent.frozen_proposal_hash,
    effect_request_digest: digestFor('effect-intent', intent),
    idempotency_key: sha256Hex(canonicalize({ world_id: intent.world_id, ruling_id: intent.ruling_id, nonce: 'm6-token-fixture' })),
    service: intent.service,
    action_class: intent.action_class,
    expires_at: '2026-08-01T09:05:00.000Z',
  };
  return commitToken.parse(createEmbeddedMac(harness.keyring, 'commit-token', body, 'mac'));
}

async function commitFixture(context: ScenarioContext) {
  const harness = await harnessFor(context);
  const proposal = harness.proposal();
  const ruling = await harness.rule('commit', proposal);
  if (ruling.ruling.verdict !== 'allow') {
    harness.close();
    throw new Error('adversarial commitment fixture did not start from allow');
  }
  return { harness, proposal, ruling, intent: harness.intent(proposal, ruling.ruling.ruling_id) };
}

async function openEscalation(context: ScenarioContext, kind: 'conflict' | 'authority' = 'conflict') {
  const harness = await harnessFor(context);
  let result: RuleProposalResult;
  if (kind === 'authority') {
    result = await harness.rule('authorize', harness.proposal(), { tool_request_class: 'new-tool-privilege-recipient-purpose' });
  } else {
    harness.setSignals('verify', [signal('evidence_conflict')]);
    result = await harness.rule('verify', harness.proposal());
  }
  if (result.escalationId === null) {
    harness.close();
    throw new Error('adversarial escalation fixture did not open');
  }
  return { harness, result, escalationId: result.escalationId };
}

function handoffService(harness: ProductionHarness, bootId = harness.authorizationBootId, ttlMs = 30_000): CaseSessionHandoffService {
  return new CaseSessionHandoffService({
    store: harness.store,
    worldId: 'w-demo',
    authorizationBootId: bootId,
    targetOrigin: 'http://127.0.0.1:7802',
    caseExists: (caseId) => caseId === contextCase(harness),
    ttlMs,
    randomCode: () => 'b'.repeat(64),
    nextHandoffId: () => `handoff_${contextCase(harness)}`,
  });
}

function contextCase(harness: ProductionHarness): string {
  return harness.caseId.replaceAll('-', '_');
}

async function executeHandoff(context: ScenarioContext): Promise<BoundedCaseResult> {
  const harness = await harnessFor(context);
  try {
    const service = handoffService(harness, harness.authorizationBootId, context.row.id === 'adv-handoff-expired' || context.row.id === 'adv-handoff-wrong-window' ? 1_000 : 30_000);
    const minted = await service.mint(contextCase(harness), CASE_OFFICER);
    const { expires_at: ignored, ...base } = minted;
    void ignored;
    const input = { ...base, session_id: `session_${context.row.id.replaceAll('-', '_')}_${context.laneSlot.replaceAll('-', '_')}` };
    let accepted = 0;
    let defect = 'handoff-refused';
    const redeem = async (value: typeof input, actor: TransactionActor = ORCHESTRATOR, target = service) => {
      try {
        await target.redeem(value, actor);
        accepted += 1;
        return true;
      } catch (error) {
        if (error instanceof CaseSessionHandoffError) defect = error.code;
        return false;
      }
    };
    switch (context.row.id) {
      case 'adv-handoff-wrong-origin':
      case 'adv-handoff-wrong-target-origin':
        await redeem({ ...input, target_origin: 'http://127.0.0.1:7999' });
        break;
      case 'adv-handoff-opaque-origin':
        await redeem({ ...input, target_origin: 'null' });
        break;
      case 'adv-handoff-wrong-window':
      case 'adv-handoff-expired':
        harness.setNow('2026-08-01T09:00:02.000Z');
        await redeem(input);
        break;
      case 'adv-handoff-wrong-world':
        await redeem({ ...input, world_id: 'w-other' });
        break;
      case 'adv-handoff-wrong-case':
        await redeem({ ...input, case_id: 'case_other' });
        break;
      case 'adv-handoff-wrong-role':
        await redeem({ ...input, role: 'principal' as never });
        break;
      case 'adv-handoff-replay':
        await redeem(input);
        await redeem({ ...input, session_id: `${input.session_id}_replay` });
        break;
      case 'adv-handoff-concurrent-redemption': {
        const outcomes = await Promise.all([
          redeem(input),
          redeem({ ...input, session_id: `${input.session_id}_other` }),
        ]);
        if (outcomes.filter(Boolean).length !== 1) throw new Error('concurrent handoff redemption did not linearize');
        break;
      }
      case 'adv-handoff-missing-process-auth':
        await redeem(input, CASE_OFFICER);
        break;
      case 'adv-handoff-authz-restart':
        await redeem(input, ORCHESTRATOR, handoffService(harness, 'authz_boot_restarted'));
        break;
      case 'adv-session-orchestrator-restart': {
        await redeem(input);
        try {
          await handoffService(harness, 'authz_boot_restarted').closeSession(input.session_id, ORCHESTRATOR);
          accepted += 1;
        } catch (error) {
          if (error instanceof CaseSessionHandoffError) defect = error.code;
        }
        break;
      }
      default:
        throw new Error(`unsupported handoff case ${context.row.id}`);
    }
    const expectedAccepted = ['adv-handoff-replay', 'adv-handoff-concurrent-redemption', 'adv-session-orchestrator-restart'].includes(context.row.id) ? 1 : 0;
    if (accepted !== expectedAccepted) throw new Error(`${context.row.id} did not produce its single-use handoff boundary`);
    return failureResult(context, defect, 'case-session-handoff-service', [
      { name: 'accepted_count', observed: accepted },
      { name: 'durable_handoff_count', observed: harness.store.snapshot().caseSessionHandoffs.size },
      { name: 'durable_session_count', observed: harness.store.snapshot().caseSessionProvenance.size },
    ]);
  } finally { harness.close(); }
}

async function executeCredentialConfinement(context: ScenarioContext): Promise<BoundedCaseResult> {
  const harness = await harnessFor(context);
  try {
    const adapter = new AuthorizationHttpAdapter({
      authorization: harness.core,
      ownOrigin: 'http://127.0.0.1:7801',
      demoWorldId: 'w-demo',
      credentials: [
        { label: 'role:principal', token: '1'.repeat(64), worldId: 'w-demo' },
        { label: 'role:case_officer', token: '2'.repeat(64), worldId: 'w-demo' },
        { label: 'role:applicant', token: '3'.repeat(64), worldId: 'w-demo' },
        { label: 'proc:orchestrator', token: '4'.repeat(64), worldId: 'w-demo' },
        { label: 'proc:services_host', token: '5'.repeat(64), worldId: 'w-demo' },
      ],
    });
    const token = context.row.id === 'adv-handoff-on-authority-route' ? 'b'.repeat(64) : 'session_m6_untrusted';
    let handlerReached = false;
    const response = await adapter.dispatch(
      { method: 'POST', pathname: '/w/w-demo/mandates', authorization: `Bearer ${token}`, origin: 'http://127.0.0.1:7801' },
      async () => {
        handlerReached = true;
        return { status: 500, body: { unexpected: true } };
      },
    );
    if (response.status !== 401 || handlerReached) throw new Error('non-authority credential reached authority handler');
    return failureResult(context, 'credential-not-authorized', 'authorization-http-adapter:credential-map', [
      { name: 'http_status', observed: response.status }, { name: 'handler_reached', observed: handlerReached },
    ]);
  } finally { harness.close(); }
}

export async function executeAdversarial(context: ScenarioContext): Promise<BoundedCaseResult> {
  if (context.row.id.startsWith('adv-handoff-') && !context.row.id.endsWith('-on-authority-route')) return executeHandoff(context);
  if (context.row.id === 'adv-session-orchestrator-restart') return executeHandoff(context);
  if (context.row.id === 'adv-handoff-on-authority-route' || context.row.id === 'adv-session-on-authority-route') return executeCredentialConfinement(context);

  switch (context.row.id) {
    case 'adv-service-without-token': {
      const harness = await harnessFor(context);
      try {
        const ledger = new EffectLedger({ recordsRoot: join(context.recordsRoot, 'services'), worldId: 'w-demo', bootId: 'services_boot_m6', keyring: harness.keyring, now: () => harness.now });
        const rejected = ledger.execute({}, {}, () => ({ outcome: 'success' }));
        const probe = ledger.probe('0'.repeat(64));
        if (rejected.accepted || rejected.reason !== 'malformed' || probe.state !== 'absent') throw new Error('service accepted or recorded a request without token');
        return failureResult(context, rejected.reason, 'effect-ledger:token-verification', [{ name: 'accepted', observed: rejected.accepted }, { name: 'ledger_probe_state', observed: probe.state }]);
      } finally { harness.close(); }
    }
    case 'adv-consumed-token-replay': {
      const { harness, intent } = await commitFixture(context);
      try {
        const ledger = new EffectLedger({ recordsRoot: join(context.recordsRoot, 'services'), worldId: 'w-demo', bootId: 'services_boot_m6', keyring: harness.keyring, now: () => harness.now });
        const token = mintToken(harness, intent);
        const first = ledger.execute(token, intent, () => ({ outcome: 'success' }));
        const replay = ledger.execute(token, intent, () => ({ outcome: 'success' }));
        if (!first.accepted || !replay.accepted || first.delivery !== 'executed' || replay.delivery !== 'retry') throw new Error('token replay was not idempotently contained');
        return failureResult(context, 'consumed-token-replay', 'effect-ledger:idempotency', [{ name: 'first_delivery', observed: first.delivery }, { name: 'replay_delivery', observed: replay.delivery }, { name: 'same_effect_id', observed: first.record.effect_id === replay.record.effect_id }], [], 'already_bound', 1);
      } finally { harness.close(); }
    }
    case 'adv-consumed-ruling-replay': {
      const { harness, ruling, intent } = await commitFixture(context);
      try {
        const root = join(context.recordsRoot, 'services');
        const first = await harness.services(root).execute(ruling.ruling.ruling_id, intent);
        const second = await harness.services(root).execute(ruling.ruling.ruling_id, intent);
        if (!first.ok || second.ok || second.stage !== 'commit-verify' || second.defect !== 'replayed-ruling') throw new Error('consumed ruling replay was not refused');
        return failureResult(context, second.defect, 'authorization-core:ruling-single-use', [{ name: 'first_effect', observed: first.ok }, { name: 'replay_refused', observed: !second.ok }, { name: 'effect_count', observed: harness.store.snapshot().effects.size }], [ruling], 'already_bound', 1);
      } finally { harness.close(); }
    }
    case 'adv-ruling-wrong-proposal': {
      const { harness, ruling, proposal } = await commitFixture(context);
      try {
        const other = harness.proposal();
        const intent = harness.intent(other, ruling.ruling.ruling_id);
        const result = await harness.core.commitVerify({ rulingId: ruling.ruling.ruling_id, intent, servicesHostBootId: 'services_boot_m6', servicesLedgerId: 'ledger_m6', actor: SERVICES_HOST });
        if (result.ok || result.defect !== 'proposal-mismatch') throw new Error('wrong proposal ruling was not refused');
        return failureResult(context, result.defect, 'authorization-core:frozen-proposal-binding', [{ name: 'source_hash_differs', observed: proposal.proposal_hash !== other.proposal_hash }, { name: 'commitment_count', observed: harness.store.snapshot().commitments.size }], [ruling]);
      } finally { harness.close(); }
    }
    case 'adv-proposal-mutated-after-allow': {
      const harness = await harnessFor(context);
      try {
        const proposal = harness.proposal();
        const ruled = await harness.rule('authorize', proposal);
        const mutated = { ...proposal, proposed_action: 'Mutated after allow.' } as typeof proposal;
        let code = '';
        try { await harness.rule('submit', mutated); } catch (error) { code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : ''; }
        if (code !== 'proposal-hash') throw new Error('proposal mutation did not fail hash verification');
        return failureResult(context, code, 'authorization-core:proposal-hash', [{ name: 'original_allowed', observed: ruled.ruling.verdict }, { name: 'mutated_persisted', observed: harness.store.snapshot().proposals.size > 1 }], [ruled]);
      } finally { harness.close(); }
    }
    case 'adv-overlapping-mandates': {
      const harness = await harnessFor(context);
      try {
        const { binding: ignoredBinding, ...body } = harness.mandate;
        void ignoredBinding;
        const second = bindMandate(harness.keyring, { ...body, mandate_id: 'mdt_overlapping', revocation_endpoint: '/w/w-demo/mandates/mdt_overlapping/revoke' });
        await harness.core.grantMandate(second, PRINCIPAL);
        let refused = false;
        try {
          await harness.projections().beginCall({ turn_id: 'turn_overlap', selection_id: harness.selectionId, ingress_binding: null, proposal_binding: null, revision_binding: null, actor: ORCHESTRATOR });
        } catch { refused = true; }
        if (!refused) throw new Error('overlapping mandates did not fail the sole-mandate projection boundary');
        const activeMandateCount = [...harness.store.snapshot().mandateStatus.values()].filter((status) => status.state === 'active').length;
        if (activeMandateCount !== 2) throw new Error('overlapping mandate fixture did not create two active mandates');
        return failureResult(context, 'mandate-ambiguous', 'conversation-projection:single-active-mandate', [{ name: 'active_mandate_count', observed: activeMandateCount }, { name: 'model_call_opened', observed: harness.store.snapshot().modelCalls.size }]);
      } finally { harness.close(); }
    }
    case 'adv-changed-mandate-ordering': {
      const harness = await harnessFor(context);
      try {
        const { binding: ignoredBinding, ...body } = harness.mandate;
        void ignoredBinding;
        const changed = bindMandate(harness.keyring, { ...body, version: 2, ordering_rule: 'earliest-version-wins', issued_at: harness.now });
        await harness.core.amendMandate(changed, PRINCIPAL);
        // Preserve the previously valid proposal/selection binding. The core must compare it
        // with the newly current, invalid-ordering mandate rather than accepting a caller defect.
        const proposal = harness.proposal();
        const ruled = await harness.rule('authorize', proposal);
        if (ruled.ruling.verdict !== 'deny' || ruled.ruling.matched_rule_id !== 'authority:invalid-mandate-binding') throw new Error('core did not derive the changed-ordering authority defect');
        return failureResult(context, 'invalid-mandate-binding', 'authorization-core:mandate-ordering-rule', [{ name: 'ordering_rule', observed: changed.ordering_rule }, { name: 'matched_rule', observed: ruled.ruling.matched_rule_id }, { name: 'effect_count', observed: harness.store.snapshot().effects.size }], [ruled]);
      } finally { harness.close(); }
    }
    case 'adv-revocation-before-commit':
    case 'adv-revocation-after-commit':
    case 'adv-policy-before-commit':
    case 'adv-policy-after-commit': {
      const { harness, ruling, intent } = await commitFixture(context);
      try {
        const after = context.row.id.endsWith('after-commit');
        let firstEffect = false;
        if (after) firstEffect = (await harness.services(join(context.recordsRoot, 'services')).execute(ruling.ruling.ruling_id, intent)).ok;
        if (context.row.id.startsWith('adv-revocation')) {
          await harness.core.revokeMandate(harness.mandate.mandate_id, harness.mandate.version, PRINCIPAL);
        } else {
          const changed = loadPolicyFile(POLICY_PATH, digestFor('evaluator-build', { package: 'm6-offline', changed: context.row.id }));
          await harness.core.reloadPolicy(changed, AUTHZ);
        }
        const result = await harness.core.commitVerify({ rulingId: ruling.ruling.ruling_id, intent, servicesHostBootId: 'services_boot_m6', servicesLedgerId: 'ledger_m6', actor: SERVICES_HOST });
        if (result.ok || (after && !firstEffect) || harness.store.snapshot().effects.size !== (after ? 1 : 0)) throw new Error('mid-flight authority case violated its linearization boundary');
        return failureResult(context, after ? 'already-bound-authority-change' : 'authority-invalidated-before-commit', 'authorization-core:commit-linearization', [{ name: 'change_after_commit', observed: after }, { name: 'first_effect', observed: firstEffect }, { name: 'effect_count', observed: harness.store.snapshot().effects.size }, { name: 'recheck_defect', observed: result.ok ? null : result.defect }], [ruling], after ? 'already_bound' : 'blocked', after ? 1 : 0);
      } finally { harness.close(); }
    }
    case 'adv-counter-ceiling-race': {
      const harness = await harnessFor(context, { mandateOverrides: { limits: { amount_minor_units: 100, frequency_per_day: 10, notification_volume: 5, geographic: ['CH'], time_window: { not_before: '2026-08-01T00:00:00.000Z', not_after: '2026-08-02T00:00:00.000Z' } } } });
      try {
        const make = (reference: string) => harness.proposal({ exact_parameters: { amount_minor_units: 60, reference }, cost_obligation: { amount_minor_units: 60, description: 'Synthetic amount.' } });
        const results = await Promise.all([harness.rule('commit', make('race-a')), harness.rule('commit', make('race-b'))]);
        const allowed = results.filter((result) => result.ruling.verdict === 'allow').length;
        const escalated = results.filter((result) => result.ruling.verdict === 'escalate').length;
        const reservedAmount = [...harness.store.snapshot().reservations.values()]
          .filter((reservation) => reservation.counter === 'amount' && reservation.state === 'reserved')
          .reduce((total, reservation) => total + reservation.delta, 0);
        if (allowed !== 1 || escalated !== 1 || reservedAmount !== 60) throw new Error('counter ceiling race did not serialize');
        return failureResult(context, 'aggregate-ceiling', 'world-lock:counter-reservation', [{ name: 'allowed_count', observed: allowed }, { name: 'escalated_count', observed: escalated }, { name: 'reserved_amount', observed: reservedAmount }], results);
      } finally { harness.close(); }
    }
    case 'adv-crash-after-commitment': {
      const harness = await harnessFor(context);
      try {
        await harness.prepareNativeContext();
        const caseId = context.row.id.replaceAll('-', '_');
        const lane = context.laneSlot.replaceAll('-', '_');
        const materialInputId = `said_${caseId}_${lane}`;
        const proposalRunId = `prun_${caseId}_${lane}`;
        const coordinator = new ModelTurnCoordinator({
          worldId: 'w-demo',
          caseId,
          authorization: modelAuthorization(harness),
          lanes: [laneConfig(context, async () => ({
            lane: context.laneSlot === 'lane-0' ? 'publicai' : 'openai',
            requestedId: context.selectedCard?.requested_id ?? '',
            servedId: context.selectedCard?.requested_id ?? '',
            content: nativeProposalContent(materialInputId),
            toolCalls: [],
          }))],
        });
        const frozen = await coordinator.runProposal({
          proposalRunId,
          conversationVersion: harness.store.snapshot().conversationVersionByCase.get(caseId) ?? 0,
          turnId: `turn_${caseId}_${lane}`,
          selectionId: harness.selectionId,
          cardId: context.selectedCard?.card_id ?? '',
          cardVersion: context.selectedCard?.card_version ?? 0,
          requestedId: context.selectedCard?.requested_id ?? '',
        }, { onBehalfOf: { role: 'case_officer', session_id: harness.sessionId } });
        const proposal = harness.store.snapshot().proposals.get(frozen.proposal.proposal_id);
        if (proposal === undefined) throw new Error('native recovery fixture lost its frozen proposal');
        const precommit = await harness.proposalPrecommit.run(proposal.proposal_id, ORCHESTRATOR);
        if (precommit.state !== 'verified' || precommit.gates.some((gate) => gate.verdict !== 'allow')) {
          throw new Error('native recovery fixture did not reach verified precommit');
        }
        const preparation = await harness.executionPreparations.issue(caseId, proposalRunId, harness.sessionId, ORCHESTRATOR);
        const services = harness.nativeServices(join(context.recordsRoot, 'services'));
        const committed = await harness.executionPreparations.commitVerify(
          preparation.execution_preparation_id,
          services.ledger.bootId,
          services.ledger.ledgerId,
          SERVICES_HOST,
        );
        if (committed.state !== 'committed') throw new Error('native recovery fixture did not stop after commitment');
        const recovery = await services.executePrepared('w-demo', preparation.execution_preparation_id);
        const ledgerProbe = services.ledger.probe(committed.token.idempotency_key);
        const state = harness.store.snapshot();
        const commitment = state.commitments.get(committed.commitment_id);
        const commitRuling = state.rulings.get(committed.ruling.ruling_id);
        if (
          recovery.state !== 'indeterminate' ||
          recovery.effect_outcome !== 'unknown-reconciliation-required' ||
          ledgerProbe.state !== 'absent' ||
          commitment?.state !== 'bound' ||
          commitRuling?.verdict !== 'allow' ||
          state.effects.size !== 0
        ) throw new Error('services-host recovery did not preserve the commitment without duplicating an effect');
        return failureResult(
          context,
          recovery.effect_outcome,
          'services-host:already-consumed-ledger-probe',
          [
            { name: 'execution_preparation_state', observed: state.executionPreparations.get(preparation.execution_preparation_id)?.state ?? null },
            { name: 'recovery_state', observed: recovery.state },
            { name: 'recovery_effect_outcome', observed: recovery.effect_outcome },
            { name: 'ledger_probe_state', observed: ledgerProbe.state },
            { name: 'commit_ruling_verdict', observed: commitRuling.verdict },
            { name: 'commitment_count', observed: state.commitments.size },
            { name: 'commitment_state', observed: commitment.state },
            { name: 'effect_count', observed: state.effects.size },
          ],
          [],
          'committed',
          state.effects.size,
        );
      } finally { harness.close(); }
    }
    case 'adv-illegal-stage-transition': {
      const state = createWorldState('w-demo');
      const at = '2026-08-01T09:00:00.000Z';
      applyWorldOp(state, { op: 'nonce.issue', nonce: { world_id: 'w-demo', nonce_id: 'nce_m6', ruling_id: 'rul_m6', expires_at: '2026-08-01T09:05:00.000Z', state: 'issued' } }, at);
      applyWorldOp(state, { op: 'nonce.consume', nonce_id: 'nce_m6' }, at);
      let refused = false;
      try { applyWorldOp(state, { op: 'nonce.consume', nonce_id: 'nce_m6' }, at); } catch { refused = true; }
      if (!refused) throw new Error('illegal nonce transition was accepted');
      return failureResult(context, 'illegal-transition', 'state-machine:nonce-single-use', [{ name: 'second_consume_refused', observed: refused }, { name: 'nonce_state', observed: state.nonces.get('nce_m6')?.state ?? null }]);
    }
    case 'adv-late-approval': {
      const { harness, result, escalationId } = await openEscalation(context, 'authority');
      try {
        harness.setNow('2026-08-01T09:16:00.000Z');
        const late = await harness.core.disposeEscalation({ escalationId, disposition: 'deny', actor: PRINCIPAL });
        if (late.accepted) throw new Error('late disposition was accepted');
        return failureResult(context, 'late-disposition', 'authorization-core:response-bound', [{ name: 'accepted', observed: late.accepted }, { name: 'terminal_state', observed: harness.store.snapshot().escalations.get(escalationId)?.state ?? null }, { name: 'commitment_count', observed: harness.store.snapshot().commitments.size }], [result]);
      } finally { harness.close(); }
    }
    case 'adv-disposition-wrong-role':
    case 'adv-disposition-unauthorized-substitute': {
      const { harness, result, escalationId } = await openEscalation(context, context.row.id.endsWith('unauthorized-substitute') ? 'authority' : 'conflict');
      try {
        const actor = context.row.id.endsWith('unauthorized-substitute') ? CASE_OFFICER : APPLICANT;
        const disposed = await harness.core.disposeEscalation({ escalationId, disposition: 'deny', actor });
        if (disposed.accepted || disposed.defect !== 'wrong-role') throw new Error('wrong disposition role was accepted');
        return failureResult(context, disposed.defect, 'authorization-core:intervention-standing', [{ name: 'accepted', observed: disposed.accepted }, { name: 'escalation_state', observed: harness.store.snapshot().escalations.get(escalationId)?.state ?? null }], [result]);
      } finally { harness.close(); }
    }
    case 'adv-disposition-outside-set': {
      const { harness, result, escalationId } = await openEscalation(context);
      try {
        const before = harness.store.snapshot().actionRecords.length;
        let refused = false;
        try { await harness.core.disposeEscalation({ escalationId, disposition: 'reverse' as never, actor: CASE_OFFICER }); } catch { refused = true; }
        if (!refused || harness.store.snapshot().actionRecords.length !== before) throw new Error('outside-set disposition reached persistence');
        return failureResult(context, 'disposition-outside-set', 'authorization-core:closed-disposition-schema', [{ name: 'refused_before_transaction', observed: refused }, { name: 'action_record_delta', observed: harness.store.snapshot().actionRecords.length - before }], [result]);
      } finally { harness.close(); }
    }
    case 'adv-escalation-missing-contract-field': {
      const { harness, result, escalationId } = await openEscalation(context);
      try {
        const stateBefore = harness.store.snapshot();
        const source = stateBefore.escalations.get(escalationId);
        if (source === undefined) throw new Error('contract-refusal fixture lost its source escalation');
        const { record_and_feedback: omitted, ...incompleteContract } = source.contract;
        void omitted;
        const threatenedId = `${escalationId}_missing_contract`;
        let refused = false;
        try {
          await harness.store.transact(
            'm6_incomplete_intervention_contract',
            AUTHZ,
            [{
              op: 'escalation.open',
              escalation: {
                ...source,
                escalation_id: threatenedId,
                contract: incompleteContract,
              },
            } as never],
            harness.now,
          );
        } catch {
          refused = true;
        }
        const stateAfter = harness.store.snapshot();
        if (!refused || stateAfter.escalations.size !== stateBefore.escalations.size || stateAfter.escalations.has(threatenedId)) {
          throw new Error('incomplete intervention contract reached the durable escalation state');
        }
        return failureResult(
          context,
          'invalid-intervention-contract',
          'wal-transaction:intervention-contract',
          [
            { name: 'wal_transaction_refused', observed: refused },
            { name: 'durable_escalation_count_before', observed: stateBefore.escalations.size },
            { name: 'durable_escalation_count_after', observed: stateAfter.escalations.size },
            { name: 'threatened_escalation_present', observed: stateAfter.escalations.has(threatenedId) },
          ],
          [result],
        );
      } finally { harness.close(); }
    }
    case 'adv-concurrent-dispositions': {
      const { harness, result, escalationId } = await openEscalation(context);
      try {
        const outcomes = await Promise.all([
          harness.core.disposeEscalation({ escalationId, disposition: 'deny', actor: CASE_OFFICER }),
          harness.core.disposeEscalation({ escalationId, disposition: 'cancel', actor: PRINCIPAL }),
        ]);
        const accepted = outcomes.filter((outcome): outcome is Extract<DisposeEscalationResult, { accepted: true }> => outcome.accepted).length;
        if (accepted !== 1) throw new Error('concurrent dispositions did not linearize');
        return failureResult(context, 'single-use-escalation', 'world-lock:escalation-disposition', [{ name: 'accepted_count', observed: accepted }, { name: 'terminal_disposition', observed: harness.store.snapshot().escalations.get(escalationId)?.terminal_disposition ?? null }], [result]);
      } finally { harness.close(); }
    }
    default: throw new Error(`unknown adversarial executor ${context.row.id}`);
  }
}
