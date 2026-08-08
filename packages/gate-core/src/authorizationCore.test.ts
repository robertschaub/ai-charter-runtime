// SPDX-License-Identifier: AGPL-3.0-only
import { appendFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  AuthorizationCore,
  bindMandate,
  freezeProposal,
  type IdFactory,
  type RegistryEvidence,
  type RegistryEvidenceCitation,
} from './authorizationCore.js';
import { verifyChain } from './chain.js';
import { AuthorizationHttpAdapter } from './authorizationHttpAdapter.js';
import { AuthorizationHttpServer } from './authorizationHttpServer.js';
import type { AuthorizationReadSide } from './authorizationReadSide.js';
import type { CaseSessionHandoffService } from './caseSessionHandoff.js';
import type { ConversationProjectionService } from './conversationProjectionService.js';
import type { ConversationTransportService } from './conversationTransport.js';
import { digestFor } from './hash.js';
import { Keyring, verifyEmbeddedMac } from './keyring.js';
import { loadPolicyFile, type LoadedPolicy } from './policyLoader.js';
import {
  recordEntry,
  systemUseDecisionRecord,
  type EffectIntent,
  type FrozenProposal,
  type Mandate,
  type ScreeningSignal,
} from './schemas/index.js';
import { applyWorldTransaction, cloneWorldState, counterValue } from './state.js';
import { runSweeper } from './sweeper.js';
import { verifyCommitTokenForIntent } from './tokenVerifier.js';
import { WalStore } from './walStore.js';
import {
  createSyntheticSystemUseDecision,
  syntheticSystemUseForTests,
  systemUseDecisionDigest,
  SystemUseDecisionService,
} from './systemUseDecision.js';

const KEY_ID = 'hmac-test';
const KEY = 'a'.repeat(64);
const CARD_DIGEST = 'c'.repeat(64);
const BUILD_DIGEST = 'b'.repeat(64);
const SERVICES_LEDGER_ID = 'ledger_test';
const POLICY_FILE = fileURLToPath(new URL('../policy/v1.yaml', import.meta.url));
const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: 'case_officer' } as const;
const SERVICES_HOST = { credential: 'proc:services_host', claimed_role: null } as const;
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const CASE_OFFICER = { credential: 'role:case_officer', claimed_role: 'case_officer' } as const;
const APPLICANT = { credential: 'role:applicant', claimed_role: 'applicant' } as const;

class SequentialIds implements IdFactory {
  #next = 0;
  next(prefix: Parameters<IdFactory['next']>[0]): string {
    this.#next += 1;
    return `${prefix}_${this.#next}`;
  }
}

interface Harness {
  readonly root: string;
  readonly keyring: Keyring;
  readonly policy: LoadedPolicy;
  readonly ids: SequentialIds;
  readonly store: WalStore;
  readonly core: AuthorizationCore;
  readonly systemUse: SystemUseDecisionService;
  setNow(value: string): void;
  setScreening(proposalId: string, value: readonly ScreeningSignal[] | Error): void;
}

const roots: string[] = [];
const openStores: WalStore[] = [];

afterEach(() => {
  for (const store of openStores.splice(0)) {
    try {
      store.close();
    } catch {}
  }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(
  initialNow = '2026-08-01T09:00:00.000Z',
  options: {
    readonly dialogue?: boolean;
    readonly resolveRegistryEvidence?: (citation: RegistryEvidenceCitation) => RegistryEvidence | null;
  } = {},
): Harness {
  const root = mkdtempSync(join(tmpdir(), 'gate-core-m2-'));
  roots.push(root);
  let now = initialNow;
  const loadedPolicy = loadPolicyFile(POLICY_FILE, BUILD_DIGEST);
  const policy: LoadedPolicy = options.dialogue
    ? {
        ...loadedPolicy,
        policy: {
          ...loadedPolicy.policy,
          rules: [
            {
              id: 'dialogue-third-party-fact',
              priority: 200,
              gate: 'commit',
              matcher: { kind: 'field', source: 'context', path: ['dialogue_trigger'], operator: 'eq', value: true },
              verdict: 'escalate',
              ux_class: 'stop',
              reason_template: 'Can the applicant confirm the cited third-party registry fact?',
              intervention_contract: {
                trigger_and_state: { trigger: 'unconfirmed-inference-as-fact', state: 'open' },
                decision_and_route: {
                  eligible_role: 'applicant',
                  standing_class: 'third-party-fact',
                  competence_declared: 'Synthetic applicant response (declared, not verified).',
                  independence_declared: 'Same-operator POC; no independent reviewer exists.',
                  substitute_roles: [],
                  substitute_rule: 'A bare assertion cannot confirm a third party fact.',
                },
                decision_basis_shown: ['inf_7', 'registry read reg:CH-0042'],
                response_bound_and_default: {
                  response_bound_ms: 900_000,
                  safe_default: {
                    kind: 'stop-remains',
                    disposition: 'abstain',
                    authority_basis: { kind: 'no-new-authority' },
                    reversible: true,
                  },
                },
                permitted_dispositions: ['confirm', 'correct', 'narrow', 'permit', 'abstain', 'route'],
                record_and_feedback: {
                  record_events: ['dialogue_trigger_raised', 'dialogue_response_recorded'],
                  feedback_consequence: 'Increment the dialogue ask-rate counter.',
                },
              },
            },
            ...loadedPolicy.policy.rules,
          ],
        },
      }
    : loadedPolicy;
  const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
  const ids = new SequentialIds();
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId: 'run_1',
    bootId: 'authz_boot_1',
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: policy.evaluatorBuildDigest,
    now: () => now,
  });
  openStores.push(store);
  const screenings = new Map<string, readonly ScreeningSignal[] | Error>();
  const systemUse = syntheticSystemUseForTests(store);
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    systemUse,
    ids,
    resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
    resolveScreening: (proposal) => {
      const value = screenings.get(proposal.proposal_id) ?? [];
      if (value instanceof Error) throw value;
      return { performed: true, signals: value, evidenceRefs: [] };
    },
    validateScreeningResolution: () => true,
    resolveModelEvidence: () => ({
      servedModelAccepted: true,
      cardStatus: 'current',
      cardKeyId: 'card-test',
      cardDigest: CARD_DIGEST,
    }),
    ...(options.resolveRegistryEvidence === undefined
      ? {}
      : {
          resolveRegistryEvidence: (citation: RegistryEvidenceCitation) =>
            options.resolveRegistryEvidence?.(citation) ?? null,
        }),
  });
  return {
    root,
    keyring,
    policy,
    ids,
    store,
    core,
    systemUse,
    setNow: (value) => (now = value),
    setScreening: (proposalId, value) => screenings.set(proposalId, value),
  };
}

function conflictSignal(rationale = 'Synthetic conflict.'): ScreeningSignal {
  return {
    kind: 'screening_signal',
    signal: 'evidence_conflict',
    confidence_pct: 100,
    rationale,
    model_id: 'screening-model',
    model_version_reported: 'screening-model-v1',
  };
}

function mandateBody(
  overrides: Partial<Omit<Mandate, 'binding'>> = {},
): Omit<Mandate, 'binding'> {
  return {
    world_id: 'w-demo',
    mandate_id: 'mdt_demo',
    version: 1,
    state: 'active',
    ordering_rule: 'latest-version-wins',
    principal: { id: 'principal' },
    authorized_agent: { id: 'agent_demo' },
    authority_chain: [
      { hop: 0, delegator: 'principal', delegate: 'agent_demo', subdelegation_scope: ['grant-filing'] },
    ],
    action_class: 'grant-filing',
    connected_service: 'filing',
    target: { recipient: 'grant-office', resource: 'application-42' },
    permitted_data_fields: ['applicant_name'],
    disclosure_destinations: ['filing'],
    limits: {
      amount_minor_units: 100,
      frequency_per_day: 10,
      notification_volume: 5,
      geographic: ['CH'],
      time_window: { not_before: '2026-08-01T00:00:00.000Z', not_after: '2026-08-02T00:00:00.000Z' },
    },
    declared_purpose: 'Process the synthetic grant.',
    user_objective: 'File the synthetic grant.',
    issued_at: '2026-08-01T08:00:00.000Z',
    expires_at: '2026-08-02T00:00:00.000Z',
    revocation_endpoint: '/w/w-demo/mandates/mdt_demo/revoke',
    replay_protection: { scheme: 'per-ruling-nonce' },
    substitution_rules: { model_substitution: 'approved-set-only', service_substitution: 'named-services-only' },
    risk_class: 'medium',
    reversibility_class: 'partially-reversible',
    approved_models: [
      {
        card_id: 'model-demo',
        card_version: 1,
        card_digest: CARD_DIGEST,
        requested_id: 'model-demo-v1',
        roles: ['acting'],
        data_classes: { acting: ['conf:case', 'purpose:grant-assessment'] },
      },
    ],
    default_acting_model: { card_id: 'model-demo', card_version: 1, requested_id: 'model-demo-v1' },
    ...overrides,
  };
}

function proposal(
  sequence: number,
  overrides: Partial<Omit<FrozenProposal, 'proposal_hash'>> = {},
): FrozenProposal {
  return freezeProposal({
    world_id: 'w-demo',
    proposal_id: `prp_${sequence}`,
    revision: 1,
    action_id: `act_${sequence}`,
    created_at: '2026-08-01T09:00:00.000Z',
    declared_objective: 'File the synthetic grant.',
    proposed_action: 'Submit the grant filing.',
    target: { recipient: 'grant-office', resource: 'application-42' },
    exact_parameters: { amount_minor_units: 50, reference: `case-${sequence}` },
    material_inputs: [],
    derived_claims: [],
    data_to_be_disclosed: ['applicant_name'],
    cost_obligation: { amount_minor_units: 50, description: 'Synthetic amount.' },
    material_consequences: ['Synthetic public-funds commitment.'],
    reversibility_class: 'partially-reversible',
    commercial_influence: { applicable: false, note: 'n/a' },
    selection_id: 'sel_test_current',
    acting_model: {
      requested_id: 'model-demo-v1',
      served_id: 'model-demo-v1',
      card_id: 'model-demo',
      card_version: 1,
    },
    mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
    ...overrides,
  });
}

function ruleInput(value: FrozenProposal, overrides: Record<string, unknown> = {}) {
  return {
    gate: 'commit' as const,
    proposal: value,
    service: 'filing',
    actionClass: 'grant-filing',
    actor: ORCHESTRATOR,
    ...overrides,
  };
}

function intentFor(value: FrozenProposal, rulingId: string, service = 'filing', actionClass = 'grant-filing'): EffectIntent {
  return {
    world_id: value.world_id,
    ruling_id: rulingId,
    frozen_proposal_hash: value.proposal_hash,
    service,
    action_class: actionClass,
    target: value.target,
    exact_parameters: value.exact_parameters,
    data_to_be_disclosed: value.data_to_be_disclosed,
  };
}

async function installTestSelection(
  value: Harness,
  bound: Mandate,
  caseId = 'case_1',
  selectionId = 'sel_test_current',
): Promise<string> {
  const at = '2026-08-01T09:00:00.000Z';
  const policy = value.store.snapshot().policy;
  if (policy === undefined) throw new Error('test policy was not activated');
  const systemUse = value.systemUse.resolve(value.store.snapshot(), bound, policy.policy_version, at);
  const predecessorSelectionId = value.store.snapshot().currentModelSelectionByCase.get(caseId) ?? null;
  const checkId = `msc_${selectionId}`;
  const target = {
    ...bound.default_acting_model,
    card_digest: bound.approved_models.find(
      (entry) =>
        entry.card_id === bound.default_acting_model.card_id &&
        entry.card_version === bound.default_acting_model.card_version &&
        entry.requested_id === bound.default_acting_model.requested_id,
    )?.card_digest ?? CARD_DIGEST,
    verifying_key_id: 'card-test',
  };
  await value.store.transact(
    'test_model_selection_check',
    ORCHESTRATOR,
    [{
      op: 'model_selection_check.issue',
      check: {
        kind: 'model_selection_check',
        world_id: bound.world_id,
        check_id: checkId,
        authorization_boot_id: 'authz_boot_1',
        case_id: caseId,
        authenticated_actor: 'proc:orchestrator',
        expected_current_selection_id: predecessorSelectionId,
        mandate_id: bound.mandate_id,
        mandate_version: bound.version,
        target,
        system_use_decision: systemUse,
        policy_version: policy.policy_version,
        policy_content_digest: policy.policy_content_digest,
        evaluator_build_id: policy.evaluator_build_id,
        issued_at: at,
        expires_at: '2026-08-01T09:05:00.000Z',
        state: 'issued',
        consumed_at: null,
      },
    }],
    at,
  );
  await value.store.transact(
    'test_model_selection_apply',
    ORCHESTRATOR,
    [
      { op: 'model_selection_check.consume', check_id: checkId, consumed_at: at },
      {
        op: 'model_selection.append',
        selection: {
          world_id: bound.world_id,
          selection_id: selectionId,
          case_id: caseId,
          kind: predecessorSelectionId === null ? 'initial' : 'switch',
          predecessor_selection_id: predecessorSelectionId,
          mandate_id: bound.mandate_id,
          mandate_version: bound.version,
          target,
          system_use_decision: systemUse,
          check_id: checkId,
          selected_at: at,
          authority_effect: 'none',
        },
      },
    ],
    at,
  );
  return selectionId;
}

async function initialize(
  value: Harness,
  body = mandateBody(),
  caseId = 'case_1',
  selectionId = 'sel_test_current',
): Promise<Mandate> {
  await value.core.activatePolicy();
  const bound = bindMandate(value.keyring, body);
  await value.core.grantMandate(bound, PRINCIPAL);
  await installTestSelection(value, bound, caseId, selectionId);
  return bound;
}

describe('M2 authorization transactions', () => {
  it('requires a current system-use decision before a mandate can create a case', async () => {
    const missing = harness();
    const environment = {
      systemId: 'ai-charter-runtime-poc',
      useCaseId: 'public-grant-decision',
      jurisdictions: ['synthetic-demo'],
      hardConditions: { 'synthetic-data-only': true },
    } as const;
    const noDecision = new SystemUseDecisionService(missing.store, environment);
    const makeCore = (systemUse: SystemUseDecisionService) =>
      new AuthorizationCore({
        store: missing.store,
        keyring: missing.keyring,
        policy: missing.policy,
        systemUse,
        ids: missing.ids,
        resolveAuthorizedAgent: () => 'agent_demo',
        resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
        validateScreeningResolution: () => true,
        resolveModelEvidence: () => ({
          servedModelAccepted: true,
          cardStatus: 'current',
          cardKeyId: 'card-test',
          cardDigest: CARD_DIGEST,
        }),
      });
    const missingCore = makeCore(noDecision);
    await missingCore.activatePolicy();
    await expect(missingCore.grantMandate(bindMandate(missing.keyring, mandateBody()), PRINCIPAL)).rejects.toMatchObject({
      code: 'system-use-unavailable',
    });
    expect(missing.store.snapshot().mandates.size).toBe(0);

    const conditional = new SystemUseDecisionService(
      missing.store,
      { ...environment, hardConditions: { 'synthetic-data-only': false } },
      (mandateValue, policyVersion, systemEnvironment, at) => {
        const base = createSyntheticSystemUseDecision(mandateValue, policyVersion, systemEnvironment, at);
        const unsigned = systemUseDecisionRecord.parse({
          ...base,
          decision: {
            ...base.decision,
            status: 'approved_with_conditions',
            conditions: [{ id: 'synthetic-data-only', kind: 'hard_precondition' }],
          },
          trace: { ...base.trace, record_digest: '0'.repeat(64) },
        });
        return systemUseDecisionRecord.parse({
          ...unsigned,
          trace: { ...unsigned.trace, record_digest: systemUseDecisionDigest(unsigned) },
        });
      },
    );
    await expect(makeCore(conditional).grantMandate(bindMandate(missing.keyring, mandateBody()), PRINCIPAL)).rejects.toMatchObject({
      code: 'system-use-unavailable',
    });
    expect(missing.store.snapshot().systemUseDecisions.size).toBe(0);
    expect(missing.store.snapshot().mandates.size).toBe(0);
  });

  it('eagerly invalidates a ruling and commit authority when its system-use decision terminates', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(63, { action_id: 'act_system_use_invalidation' });
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    expect(ruled.ruling.verdict).toBe('allow');
    await h.systemUse.transition('sud_test_fixture', 1, 'suspended', AUTHZ);
    const state = h.store.snapshot();
    expect(state.rulings.get(ruled.ruling.ruling_id)?.status).toBe('invalidated');
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(state.reservations.get(reservation.id)?.state).toBe('released');
    }
    expect(
      await h.core.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: intentFor(frozen, ruled.ruling.ruling_id),
        servicesHostBootId: 'services_boot_system_use',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ).toMatchObject({ ok: false });
    expect(h.store.snapshot().commitments.size).toBe(0);
    await expect(h.core.ruleProposal(ruleInput(proposal(64)))).rejects.toMatchObject({ code: 'system-use-unavailable' });
  });

  it('preserves truthful current-at-record facts when a bound effect reports after decision termination', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(65, { action_id: 'act_system_use_late_effect' });
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_system_use_effect',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');
    expect(h.store.snapshot().commitments.get(committed.commitmentId)?.system_use_current_at_bind).toBe(true);

    await h.systemUse.transition('sud_test_fixture', 1, 'withdrawn', AUTHZ);
    await expect(
      h.core.reportEffectOutcome({
        worldId: 'w-demo',
        commitmentId: committed.commitmentId,
        effectId: committed.token.effect_id,
        idempotencyKey: committed.token.idempotency_key,
        effectRequestDigest: committed.token.effect_request_digest,
        servicesHostBootId: 'services_boot_system_use_effect',
        servicesLedgerId: SERVICES_LEDGER_ID,
        outcome: 'success',
        recordedAt: '2026-08-01T09:00:00.500Z',
        delivery: 'executed',
        actor: SERVICES_HOST,
      }),
    ).resolves.toMatchObject({ accepted: true, status: 'recorded' });
    expect(h.store.snapshot().effects.get(committed.token.effect_id)).toMatchObject({
      system_use_decision: ruled.ruling.binding.system_use_decision,
      system_use_current_at_record: false,
    });
    expect(
      h.store.snapshot().actionRecords.find(
        (entry) => entry.commitment_and_effect?.event === 'effect_outcome' && entry.commitment_and_effect.effect_id === committed.token.effect_id,
      ),
    ).toMatchObject({
      system_use_current_at_record: false,
      commitment_and_effect: { system_use_current_at_record: false },
    });
  });

  it('uses restarted condition configuration for current-at-record evidence without minting fresh authority', async () => {
    const h = harness();
    const mandateValue = await initialize(h);
    const prior = [...h.store.snapshot().systemUseDecisions.values()][0];
    if (prior === undefined) throw new Error('expected system-use fixture');
    const unsignedSuccessor = systemUseDecisionRecord.parse({
      ...prior,
      version: 2,
      decision: {
        ...prior.decision,
        status: 'approved_with_conditions',
        conditions: [{ id: 'synthetic-data-only', kind: 'hard_precondition' }],
      },
      trace: {
        ...prior.trace,
        record_digest: '0'.repeat(64),
        supersedes: { decision_id: prior.decision_id, version: prior.version },
      },
    });
    await h.systemUse.replace(
      systemUseDecisionRecord.parse({
        ...unsignedSuccessor,
        trace: {
          ...unsignedSuccessor.trace,
          record_digest: systemUseDecisionDigest(unsignedSuccessor),
        },
      }),
      AUTHZ,
    );
    const selectionId = await installTestSelection(h, mandateValue, 'case_1', 'sel_condition_current');
    const frozen = proposal(66, {
      action_id: 'act_system_use_condition_drift',
      selection_id: selectionId,
    });
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_system_use_condition',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');

    const restartedSystemUse = new SystemUseDecisionService(h.store, {
      systemId: 'ai-charter-runtime-poc',
      useCaseId: 'public-grant-decision',
      jurisdictions: ['synthetic-demo'],
      hardConditions: { 'no-external-effect': true, 'synthetic-data-only': false },
    });
    const restartedCore = new AuthorizationCore({
      store: h.store,
      keyring: h.keyring,
      policy: h.policy,
      systemUse: restartedSystemUse,
      ids: h.ids,
      resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'current',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const before = h.store.snapshot();
    await expect(restartedCore.ruleProposal(ruleInput(proposal(67)))).rejects.toMatchObject({
      code: 'system-use-unavailable',
    });
    expect(h.store.snapshot().rulings.size).toBe(before.rulings.size);
    expect(h.store.snapshot().commitments.size).toBe(before.commitments.size);

    await expect(
      restartedCore.reportEffectOutcome({
        worldId: 'w-demo',
        commitmentId: committed.commitmentId,
        effectId: committed.token.effect_id,
        idempotencyKey: committed.token.idempotency_key,
        effectRequestDigest: committed.token.effect_request_digest,
        servicesHostBootId: 'services_boot_system_use_condition',
        servicesLedgerId: SERVICES_LEDGER_ID,
        outcome: 'success',
        recordedAt: '2026-08-01T09:00:00.500Z',
        delivery: 'executed',
        actor: SERVICES_HOST,
      }),
    ).resolves.toMatchObject({ accepted: true, status: 'recorded' });
    expect(h.store.snapshot().effects.get(committed.token.effect_id)).toMatchObject({
      system_use_decision: ruled.ruling.binding.system_use_decision,
      system_use_current_at_record: false,
    });
    expect(
      h.store.snapshot().actionRecords.find(
        (entry) => entry.commitment_and_effect?.event === 'effect_outcome' && entry.commitment_and_effect.effect_id === committed.token.effect_id,
      ),
    ).toMatchObject({
      system_use_current_at_record: false,
      commitment_and_effect: { system_use_current_at_record: false },
    });
  });

  it('keeps case-scoped conversation ingestion authorization-owned and idempotent', async () => {
    const h = harness();
    await initialize(h);
    const item = {
      id: 'said_case_scope',
      store: 'said' as const,
      turn: 'turn_case_scope',
      text: 'Synthetic case-scoped testimony.',
      provenance: { derived_from: [], hops: [] },
      tags: ['conf:case', 'purpose:grant-assessment'],
      origin_actor: 'applicant' as const,
    };
    await expect(
      h.core.putConversationItems({ caseId: 'case_a', items: [item], actor: ORCHESTRATOR }),
    ).rejects.toMatchObject({ code: 'unauthorized-actor' });
    await h.core.putConversationItems({ caseId: 'case_a', items: [item], actor: AUTHZ });
    await h.core.putConversationItems({ caseId: 'case_a', items: [item], actor: AUTHZ });
    await expect(
      h.core.putConversationItems({ caseId: 'case_b', items: [item], actor: AUTHZ }),
    ).rejects.toMatchObject({ code: 'proposal-conflict' });
    expect(h.store.snapshot().storeItems.get(item.id)).toEqual({
      world_id: 'w-demo',
      case_id: 'case_a',
      item,
    });
  });

  it('rejects an unsafe world id before creating any path outside the records root', () => {
    const root = mkdtempSync(join(tmpdir(), 'gate-core-world-'));
    roots.push(root);
    const escaped = `${root}-escaped`;
    expect(() =>
      WalStore.open({
        recordsRoot: root,
        worldId: `../${basename(escaped)}`,
        runId: 'run_1',
        bootId: 'authz_boot_1',
        policyVersion: 'test',
        policyContentDigest: 'c'.repeat(64),
        evaluatorBuildDigest: BUILD_DIGEST,
      }),
    ).toThrow();
    expect(existsSync(escaped)).toBe(false);
  });

  it('refuses mandate authority changes from the orchestrator credential', async () => {
    const h = harness();
    await h.core.activatePolicy();
    const first = bindMandate(h.keyring, mandateBody());
    await expect(h.core.grantMandate(first, ORCHESTRATOR)).rejects.toMatchObject({
      code: 'unauthorized-actor',
    });
    expect(h.store.snapshot().mandates.size).toBe(0);

    await h.core.grantMandate(first, PRINCIPAL);
    const amended = bindMandate(
      h.keyring,
      mandateBody({ version: 2, issued_at: '2026-08-01T09:00:01.000Z' }),
    );
    await expect(h.core.amendMandate(amended, ORCHESTRATOR)).rejects.toMatchObject({
      code: 'unauthorized-actor',
    });
    await expect(h.core.revokeMandate('mdt_demo', 1, ORCHESTRATOR)).rejects.toMatchObject({
      code: 'unauthorized-actor',
    });
    expect(h.store.snapshot().mandateStatus.get('mdt_demo')).toMatchObject({ version: 1, state: 'active' });
  });

  it('refuses wrong-process calls across the remaining authority-changing core methods', async () => {
    const h = harness();
    await expect(h.core.activatePolicy(ORCHESTRATOR)).rejects.toMatchObject({ code: 'unauthorized-actor' });
    await h.core.activatePolicy();
    await expect(h.core.reloadPolicy(h.policy, ORCHESTRATOR)).rejects.toMatchObject({ code: 'unauthorized-actor' });
    const bound = bindMandate(h.keyring, mandateBody());
    await h.core.grantMandate(bound, PRINCIPAL);
    await installTestSelection(h, bound);
    const frozen = proposal(49);
    await expect(
      h.core.ruleProposal(ruleInput(frozen, { actor: SERVICES_HOST })),
    ).rejects.toMatchObject({ code: 'unauthorized-actor' });

    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    expect(
      await h.core.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: intentFor(frozen, ruled.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: ORCHESTRATOR,
      }),
    ).toEqual({ ok: false, defect: 'unauthorized-caller' });
    expect(h.store.snapshot().nonces.get(ruled.ruling.binding.nonce)?.state).toBe('issued');
  });

  it('seals an exact commitment before returning a token, rejects replay, and replays from WAL', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(1);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    expect(ruled.ruling.verdict).toBe('allow');
    expect(ruled.ruling.counter_reservations.map((value) => value.counter).sort()).toEqual(['actions', 'amount']);
    await h.core.activatePolicy();
    expect(h.store.snapshot().rulings.get(ruled.ruling.ruling_id)?.status).toBe('issued');

    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    expect(committed.ok).toBe(true);
    if (!committed.ok) throw new Error('expected commitment');
    expect(
      verifyEmbeddedMac(h.keyring, 'commit-token', committed.token as unknown as Record<string, unknown>, 'mac'),
    ).toBe('valid');
    expect(
      verifyCommitTokenForIntent(
        h.keyring,
        committed.token,
        intentFor(frozen, ruled.ruling.ruling_id),
        '2026-08-01T09:00:01.000Z',
      ).valid,
    ).toBe(true);
    expect(
      verifyCommitTokenForIntent(
        h.keyring,
        committed.token,
        {
          ...intentFor(frozen, ruled.ruling.ruling_id),
          target: { recipient: 'different-recipient', resource: frozen.target.resource },
        },
        '2026-08-01T09:00:01.000Z',
      ),
    ).toEqual({ valid: false, reason: 'binding-mismatch' });
    expect(
      verifyCommitTokenForIntent(
        h.keyring,
        committed.token,
        intentFor(frozen, ruled.ruling.ruling_id),
        committed.token.expires_at,
      ),
    ).toEqual({ valid: false, reason: 'expired' });

    const replay = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    expect(replay).toEqual({ ok: false, defect: 'replayed-ruling' });
    await expect(h.core.ruleProposal(ruleInput(frozen))).rejects.toMatchObject({
      code: 'proposal-already-committed',
    });

    const before = h.store.snapshot();
    expect(before.nonces.get(ruled.ruling.binding.nonce)?.state).toBe('consumed');
    expect([...before.commitments.values()][0]?.state).toBe('bound');
    expect(before.actionRecords).toHaveLength(2);
    h.store.close();
    openStores.splice(openStores.indexOf(h.store), 1);

    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_2',
      bootId: 'authz_boot_2',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.policy.evaluatorBuildDigest,
      now: () => '2026-08-01T09:01:00.000Z',
    });
    openStores.push(reopened);
    const after = reopened.snapshot();
    expect(after.commitments).toEqual(before.commitments);
    expect(after.rulings).toEqual(before.rulings);
    expect(verifyChain(join(h.root, 'w-demo', 'wal.jsonl'), 'wal-entry').ok).toBe(true);
    expect(verifyChain(join(h.root, 'w-demo', 'action.jsonl'), 'record-entry').ok).toBe(true);
  });

  it('makes duplicate concurrent ruling requests idempotent instead of minting replay capacity', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(42);

    const [first, second] = await Promise.all([
      h.core.ruleProposal(ruleInput(frozen)),
      h.core.ruleProposal(ruleInput(frozen)),
    ]);

    expect(second).toEqual(first);
    const state = h.store.snapshot();
    expect(state.rulings.size).toBe(1);
    expect(
      [...state.reservations.values()].filter((reservation) => reservation.ruling_id === first.ruling.ruling_id),
    ).toHaveLength(first.ruling.counter_reservations.length);
  });

  it('adopts one durable service outcome and records later idempotent retries without discharging twice', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(2);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');

    const report = {
      worldId: 'w-demo',
      commitmentId: committed.commitmentId,
      effectId: committed.token.effect_id,
      idempotencyKey: committed.token.idempotency_key,
      effectRequestDigest: committed.token.effect_request_digest,
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      outcome: 'success' as const,
      recordedAt: '2026-08-01T09:00:00.500Z',
      actor: SERVICES_HOST,
    };
    expect(() =>
      applyWorldTransaction(
        h.store.snapshot(),
        [{ op: 'commitment.discharge', commitment_id: committed.commitmentId, outcome: 'success' }],
        '2026-08-01T09:00:00.250Z',
      ),
    ).toThrow(/no matching durable effect outcome/);
    expect(await h.core.reportEffectOutcome({ ...report, delivery: 'executed' })).toMatchObject({
      accepted: true,
      status: 'recorded',
    });
    expect(h.store.snapshot().commitments.get(committed.commitmentId)).toMatchObject({
      state: 'discharged',
      outcome: 'success',
    });
    expect(await h.core.reportEffectOutcome({ ...report, delivery: 'retry' })).toMatchObject({
      accepted: true,
      status: 'retry-recorded',
    });
    expect(
      h.store.snapshot().actionRecords.map((entry) => entry.commitment_and_effect?.event),
    ).toContain('retry_served');
    expect(
      await h.core.reportEffectOutcome({ ...report, outcome: 'failed', delivery: 'retry' }),
    ).toEqual({ accepted: false, defect: 'conflicting-outcome' });
    expect(
      await h.core.reportEffectOutcome({
        ...report,
        delivery: 'retry',
        actor: ORCHESTRATOR,
      }),
    ).toEqual({ accepted: false, defect: 'unauthorized-reporter' });
  });

  it('holds counters on an unknown outcome, opens one pinned recovery escalation, and adopts a late service record', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(3);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');

    const reloadedSet = {
      ...h.policy.policy,
      policy_version: '2026-08-01.recovery-reroute',
      recovery_escalation_contract: {
        ...h.policy.policy.recovery_escalation_contract,
        decision_and_route: {
          ...h.policy.policy.recovery_escalation_contract.decision_and_route,
          eligible_role: 'case_officer' as const,
        },
      },
    };
    await h.core.reloadPolicy(
      { ...h.policy, policy: reloadedSet, policyContentDigest: digestFor('policy-set', reloadedSet) },
      AUTHZ,
    );

    const unknown = await h.core.markCommitmentUnknown(committed.commitmentId);
    expect(unknown).toMatchObject({ ok: true, status: 'opened' });
    if (!unknown.ok) throw new Error('expected recovery escalation');
    const afterUnknown = h.store.snapshot();
    expect(afterUnknown.commitments.get(committed.commitmentId)?.state).toBe('unknown');
    expect(afterUnknown.escalations.get(unknown.escalationId)).toMatchObject({
      state: 'open',
      source_commitment_id: committed.commitmentId,
      contract: { decision_and_route: { eligible_role: 'principal' } },
    });
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(afterUnknown.reservations.get(reservation.id)?.state).toBe('held_for_reconciliation');
    }
    expect(await h.core.markCommitmentUnknown(committed.commitmentId)).toEqual({
      ok: true,
      status: 'already-open',
      escalationId: unknown.escalationId,
    });

    expect(
      await h.core.reportEffectOutcome({
        worldId: 'w-demo',
        commitmentId: committed.commitmentId,
        effectId: committed.token.effect_id,
        idempotencyKey: committed.token.idempotency_key,
        effectRequestDigest: committed.token.effect_request_digest,
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        outcome: 'success',
        recordedAt: '2026-08-01T09:00:00.500Z',
        delivery: 'executed',
        actor: SERVICES_HOST,
      }),
    ).toMatchObject({ accepted: true, status: 'recorded' });
    const reconciled = h.store.snapshot();
    expect(reconciled.commitments.get(committed.commitmentId)).toMatchObject({
      state: 'reconciled',
      outcome: 'success',
    });
    expect(reconciled.escalations.get(unknown.escalationId)?.state).toBe('cancelled');
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(reconciled.reservations.get(reservation.id)?.state).toBe('settled');
    }
  });

  it('runs bounded same-boot probes before routing an unavailable outcome to its pinned recovery owner', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(31);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');
    let probes = 0;
    const delays: number[] = [];

    const result = await h.core.reconcileCommitment({
      commitmentId: committed.commitmentId,
      attempts: 3,
      backoffMs: [1, 2],
      delay: async (milliseconds) => {
        delays.push(milliseconds);
      },
      probe: async () => {
        probes += 1;
        return { state: 'absent' as const, boot_id: 'services_boot_1', ledger_id: SERVICES_LEDGER_ID };
      },
    });

    expect(result).toMatchObject({ resolution: 'unknown', result: { ok: true, status: 'opened' } });
    expect(probes).toBe(3);
    expect(delays).toEqual([1, 2]);
    expect(h.store.snapshot().commitments.get(committed.commitmentId)).toMatchObject({
      state: 'unknown',
      recovery_owner_role: 'principal',
    });
  });

  it('treats replacement services-ledger storage as unknown instead of proof of no effect', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(33);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');

    expect(
      await h.core.reconcileCommitment({
        commitmentId: committed.commitmentId,
        attempts: 1,
        probe: async () => ({
          state: 'absent',
          boot_id: 'services_boot_2',
          ledger_id: 'ledger_replacement',
        }),
      }),
    ).toMatchObject({ resolution: 'unknown', result: { ok: true, status: 'opened' } });
    const state = h.store.snapshot();
    expect(state.commitments.get(committed.commitmentId)?.state).toBe('unknown');
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(state.reservations.get(reservation.id)?.state).toBe('held_for_reconciliation');
    }
  });

  it('adopts a service ledger outcome found by an authorization-side reconciliation probe', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(32);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');

    expect(
      await h.core.reconcileCommitment({
        commitmentId: committed.commitmentId,
        attempts: 1,
        probe: async () => ({
          state: 'recorded',
          boot_id: 'services_boot_2',
          record: {
            world_id: 'w-demo',
            services_host_boot_id: 'services_boot_1',
            services_ledger_id: SERVICES_LEDGER_ID,
            effect_id: committed.token.effect_id,
            idempotency_key: committed.token.idempotency_key,
            effect_request_digest: committed.token.effect_request_digest,
            outcome: 'success',
            recorded_at: '2026-08-01T09:00:00.500Z',
            detail: 'Recovered synthetic service outcome.',
          },
        }),
      }),
    ).toMatchObject({ resolution: 'recorded', report: { accepted: true, status: 'recorded' } });
    const state = h.store.snapshot();
    expect(state.commitments.get(committed.commitmentId)).toMatchObject({ state: 'discharged', outcome: 'success' });
    expect(state.actionRecords.at(-1)?.authenticated_actor).toBe('proc:authz');
  });

  it('releases held counters only after an absent probe proves the services host restarted', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(4);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      servicesLedgerId: SERVICES_LEDGER_ID,
      actor: SERVICES_HOST,
    });
    if (!committed.ok) throw new Error('expected commitment');

    expect(
      await h.core.reconcileAbsentAfterRestart(
        committed.commitmentId,
        'services_boot_1',
        SERVICES_LEDGER_ID,
      ),
    ).toEqual({ ok: false, defect: 'host-still-running' });
    expect(
      await h.core.reconcileAbsentAfterRestart(
        committed.commitmentId,
        'services_boot_2',
        'different-services-ledger',
      ),
    ).toEqual({ ok: false, defect: 'ledger-continuity-mismatch' });
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(h.store.snapshot().reservations.get(reservation.id)?.state).toBe('settled');
    }
    expect(
      await h.core.reconcileAbsentAfterRestart(
        committed.commitmentId,
        'services_boot_2',
        SERVICES_LEDGER_ID,
      ),
    ).toMatchObject({ ok: true, status: 'reconciled' });
    const state = h.store.snapshot();
    expect(state.commitments.get(committed.commitmentId)).toMatchObject({
      state: 'reconciled',
      outcome: 'no-effect',
    });
    expect(state.effects.size).toBe(0);
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(state.reservations.get(reservation.id)?.state).toBe('released');
    }
  });

  it('fails closed for missing authority and denies expired, revoked, broadened, and substituted authority', async () => {
    const missing = harness();
    await missing.core.activatePolicy();
    await expect(missing.core.ruleProposal(ruleInput(proposal(1)))).rejects.toThrowError(
      /model selection sel_test_current does not exist/,
    );

    const expired = harness();
    await initialize(expired);
    expired.setNow('2026-08-03T09:00:00.000Z');
    expect((await expired.core.ruleProposal(ruleInput(proposal(2)))).ruling.reason).toContain('expired-mandate');

    const revoked = harness();
    await initialize(revoked);
    await revoked.core.revokeMandate('mdt_demo', 1, PRINCIPAL);
    expect((await revoked.core.ruleProposal(ruleInput(proposal(3)))).ruling.reason).toContain('revoked-mandate');

    const broadened = harness();
    await initialize(broadened);
    const tooLarge = proposal(4, { cost_obligation: { amount_minor_units: 101, description: 'Too large.' } });
    expect((await broadened.core.ruleProposal(ruleInput(tooLarge))).ruling.reason).toContain('broadened-request');

    const substituted = harness();
    await initialize(substituted);
    const mismatchedCore = new AuthorizationCore({
      store: substituted.store,
      keyring: substituted.keyring,
      policy: substituted.policy,
      systemUse: substituted.systemUse,
      ids: substituted.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => ({
        servedModelAccepted: false,
        cardStatus: 'current',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const result = await mismatchedCore.ruleProposal(ruleInput(proposal(5)));
    expect(result.ruling.reason).toContain('substituted-model');
  });

  it('routes ordinary card supersession to re-confirmation but fails a withdrawal closed', async () => {
    const superseded = harness();
    await initialize(superseded);
    const supersededCore = new AuthorizationCore({
      store: superseded.store,
      keyring: superseded.keyring,
      policy: superseded.policy,
      systemUse: superseded.systemUse,
      ids: superseded.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'superseded',
        cardKeyId: 'card-test',
        cardDigest: 'd'.repeat(64),
      }),
    });
    expect((await supersededCore.ruleProposal(ruleInput(proposal(6)))).ruling).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'default:model-card-reconfirmation',
    });

    const withdrawn = harness();
    await initialize(withdrawn);
    const withdrawnCore = new AuthorizationCore({
      store: withdrawn.store,
      keyring: withdrawn.keyring,
      policy: withdrawn.policy,
      systemUse: withdrawn.systemUse,
      ids: withdrawn.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'withdrawn',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const denied = await withdrawnCore.ruleProposal(ruleInput(proposal(7)));
    expect(denied.ruling.verdict).toBe('deny');
    expect(denied.ruling.reason).toContain('stale-card');
  });

  it('rechecks card trust at commit-verify and blocks a withdrawal after ruling issuance', async () => {
    const h = harness();
    await initialize(h);
    let cardStatus: 'current' | 'withdrawn' = 'current';
    const core = new AuthorizationCore({
      store: h.store,
      keyring: h.keyring,
      policy: h.policy,
      systemUse: h.systemUse,
      ids: h.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus,
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const frozen = proposal(8);
    const ruled = await core.ruleProposal(ruleInput(frozen));
    expect(ruled.ruling.verdict).toBe('allow');

    cardStatus = 'withdrawn';
    expect(
      await core.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: intentFor(frozen, ruled.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ).toEqual({ ok: false, defect: 'stale-card' });
  });

  it('converts runtime card-registry failures into recorded fail-closed decisions', async () => {
    const atRuling = harness();
    await initialize(atRuling);
    const rulingCore = new AuthorizationCore({
      store: atRuling.store,
      keyring: atRuling.keyring,
      policy: atRuling.policy,
      systemUse: atRuling.systemUse,
      ids: atRuling.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => {
        throw new Error('synthetic card reload failure');
      },
    });
    const denied = await rulingCore.ruleProposal(ruleInput(proposal(9)));
    expect(denied.ruling).toMatchObject({ verdict: 'deny', matched_rule_id: 'authority:stale-card' });
    expect(denied.ruling.reason).toContain('stale-card');
    expect(
      atRuling.store
        .snapshot()
        .actionRecords.find((entry) => entry.admissibility_decision.ruling_id === denied.ruling.ruling_id)
        ?.admissibility_decision.verdict,
    ).toBe('deny');

    const atCommit = harness();
    await initialize(atCommit);
    let registryAvailable = true;
    const commitCore = new AuthorizationCore({
      store: atCommit.store,
      keyring: atCommit.keyring,
      policy: atCommit.policy,
      systemUse: atCommit.systemUse,
      ids: atCommit.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => {
        if (!registryAvailable) throw new Error('synthetic card reload failure');
        return {
          servedModelAccepted: true,
          cardStatus: 'current',
          cardKeyId: 'card-test',
          cardDigest: CARD_DIGEST,
        };
      },
    });
    const frozen = proposal(10);
    const ruled = await commitCore.ruleProposal(ruleInput(frozen));
    expect(ruled.ruling.verdict).toBe('allow');

    registryAvailable = false;
    expect(
      await commitCore.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: intentFor(frozen, ruled.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ).toEqual({ ok: false, defect: 'stale-card' });
    const state = atCommit.store.snapshot();
    expect(state.rulings.get(ruled.ruling.ruling_id)?.status).toBe('invalidated');
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(state.reservations.get(reservation.id)?.state).toBe('released');
    }
  });

  it('records a narrow disposition, then makes the orchestrator rerun all pre-commit gates', async () => {
    const h = harness();
    await initialize(h);
    const original = proposal(11);
    h.setScreening(original.proposal_id, [conflictSignal('Two synthetic registry records conflict.')]);
    const escalated = await h.core.ruleProposal(
      ruleInput(original, { gate: 'verify' }),
    );
    expect(escalated.ruling).toMatchObject({ verdict: 'escalate', matched_rule_id: 'escalate-verify-conflict' });
    if (escalated.escalationId === null) throw new Error('expected escalation');

    expect(
      await h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'narrow-or-modify',
        actor: APPLICANT,
      }),
    ).toMatchObject({ accepted: false, defect: 'wrong-role' });
    expect(
      await h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'allow-within-scope',
        actor: CASE_OFFICER,
      }),
    ).toMatchObject({ accepted: false, defect: 'disposition-not-permitted' });
    expect(h.store.snapshot().escalations.get(escalated.escalationId)?.state).toBe('open');

    const revised = proposal(12, {
      action_id: original.action_id,
      revision: 2,
      proposed_action: 'Submit the grant filing using the uncontested registry record.',
    });
    const disposed = await h.core.disposeEscalation({
      escalationId: escalated.escalationId,
      disposition: 'narrow-or-modify',
      actor: CASE_OFFICER,
    });
    expect(disposed).toMatchObject({
      accepted: true,
      status: 'disposed',
      successor: null,
    });
    if (!disposed.accepted) throw new Error('expected accepted disposition');

    const continued = await h.core.continueEscalationRevision({
      escalationId: escalated.escalationId,
      proposal: revised,
      actor: ORCHESTRATOR,
    });
    expect(continued).toMatchObject({
      accepted: true,
      stages: [
        { ruling: { gate: 'authorize', verdict: 'allow', matched_rule_id: 'allow-grant-authorize' } },
        { ruling: { gate: 'submit', verdict: 'allow', matched_rule_id: 'allow-grant-submit' } },
        { ruling: { gate: 'verify', verdict: 'allow', matched_rule_id: 'allow-grant-verification' } },
      ],
      successor: { ruling: { gate: 'verify', verdict: 'allow' } },
    });
    if (!continued.accepted) throw new Error('expected successor ruling');

    const state = h.store.snapshot();
    expect(state.escalations.get(escalated.escalationId)).toMatchObject({
      state: 'disposed',
      terminal_disposition: 'narrow-or-modify',
      successor_ruling_id: continued.successor.ruling.ruling_id,
    });
    expect(state.rulings.get(escalated.ruling.ruling_id)).toMatchObject({
      status: 'invalidated',
      successor_ruling_id: continued.successor.ruling.ruling_id,
    });
    for (const reservation of escalated.ruling.counter_reservations) {
      expect(state.reservations.get(reservation.id)?.state).toBe('released');
    }
    const successorRecord = state.actionRecords.find(
      (entry) => entry.admissibility_decision.ruling_id === continued.successor.ruling.ruling_id,
    );
    expect(successorRecord?.basis).toContain(disposed.recordEntryId);
    expect(successorRecord?.authenticated_actor).toBe('proc:orchestrator');
    expect(
      state.actionRecords.filter(
        (entry) =>
          entry.human_intervention_event?.event === 'human_intervention_event' &&
          entry.human_intervention_event.payload.kind === 'disposition_refused',
      ),
    ).toHaveLength(2);

    expect(
      await h.core.commitVerify({
        rulingId: continued.successor.ruling.ruling_id,
        intent: intentFor(revised, continued.successor.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ).toEqual({ ok: false, defect: 'not-allowed' });

    expect(
      await h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'deny',
        actor: CASE_OFFICER,
      }),
    ).toMatchObject({ accepted: false, defect: 'late-disposition', terminalState: 'disposed' });
  });

  it('lets timeout win lazily and records a later disposition as a no-op', async () => {
    const h = harness();
    await initialize(h);
    const original = proposal(13);
    h.setScreening(original.proposal_id, [conflictSignal()]);
    const escalated = await h.core.ruleProposal(
      ruleInput(original, { gate: 'verify' }),
    );
    if (escalated.escalationId === null) throw new Error('expected escalation');
    h.setNow('2026-08-01T09:15:00.000Z');

    expect(
      await h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'deny',
        actor: CASE_OFFICER,
      }),
    ).toMatchObject({ accepted: false, defect: 'late-disposition', terminalState: 'timed_out' });
    const state = h.store.snapshot();
    expect(state.escalations.get(escalated.escalationId)).toMatchObject({
      state: 'timed_out',
      terminal_disposition: 'cancel',
    });
    expect(
      state.actionRecords.map((entry) => entry.human_intervention_event?.event),
    ).toContain('late_disposition_ignored');
    expect(
      state.actionRecords.map((entry) =>
        entry.human_intervention_event?.event === 'human_intervention_event'
          ? entry.human_intervention_event.payload.kind
          : null,
      ),
    ).toContain('escalation_timeout');
  });

  it('cancels an uncommitted escalated action and records the contract recovery owner', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(131, { action_id: 'act_cancel_mid_workflow' });
    h.setScreening(frozen.proposal_id, [conflictSignal()]);
    const ruled = await h.core.ruleProposal(ruleInput(frozen, { gate: 'verify' }));
    if (ruled.escalationId === null) throw new Error('expected escalation');
    expect(h.store.snapshot().escalations.get(ruled.escalationId)?.contract.decision_and_route.eligible_role).toBe(
      'case_officer',
    );

    const cancelled = await h.core.disposeEscalation({
      escalationId: ruled.escalationId,
      disposition: 'cancel',
      actor: CASE_OFFICER,
    });
    expect(cancelled).toMatchObject({ accepted: true, successor: null, reviewObligationId: null });
    const state = h.store.snapshot();
    expect(state.escalations.get(ruled.escalationId)).toMatchObject({
      state: 'disposed',
      terminal_disposition: 'cancel',
      successor_ruling_id: null,
    });
    expect(state.rulings.get(ruled.ruling.ruling_id)?.status).toBe('invalidated');
    expect(state.commitments.size).toBe(0);
    expect(state.actionRecords.find((entry) => entry.entry_id === cancelled.recordEntryId)?.human_intervention_event)
      .toMatchObject({ payload: { kind: 'disposition_recorded', disposition: 'cancel' } });
  });

  it('ignores caller screening claims when authorization-owned screening is unavailable', async () => {
    const h = harness();
    await initialize(h);
    const original = proposal(81);
    h.setScreening(original.proposal_id, [conflictSignal()]);
    const escalated = await h.core.ruleProposal(
      ruleInput(original, { gate: 'verify' }),
    );
    if (escalated.escalationId === null) throw new Error('expected escalation');
    expect(
      await h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'narrow-or-modify',
        actor: CASE_OFFICER,
      }),
    ).toMatchObject({ accepted: true, successor: null });
    const invalidRevision = proposal(84, { action_id: original.action_id, revision: 3 });
    expect(
      await h.core.continueEscalationRevision({
        escalationId: escalated.escalationId,
        proposal: invalidRevision,
        actor: ORCHESTRATOR,
      }),
    ).toMatchObject({
      accepted: false,
      defect: 'revision-not-permitted',
      recordEntryId: expect.any(String),
    });
    const revised = proposal(82, { action_id: original.action_id, revision: 2 });
    h.setScreening(revised.proposal_id, new Error('synthetic screening outage'));
    const untrustedContinuation = {
      escalationId: escalated.escalationId,
      proposal: revised,
      actor: ORCHESTRATOR,
      signals: [],
      screeningPerformed: true,
    } as const;
    const continued = await h.core.continueEscalationRevision(untrustedContinuation);
    expect(continued).toMatchObject({
      accepted: true,
      stages: [
        { ruling: { gate: 'authorize', verdict: 'allow' } },
        { ruling: { gate: 'submit', verdict: 'escalate', matched_rule_id: 'default:required-screening-missing' } },
      ],
    });
  });

  it('revalidates screening inside the world lock and records a fail-closed skip when evidence changed', async () => {
    const h = harness();
    await initialize(h);
    const core = new AuthorizationCore({
      store: h.store,
      keyring: h.keyring,
      policy: h.policy,
      systemUse: h.systemUse,
      ids: h.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => false,
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'current',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const ruled = await core.ruleProposal(ruleInput(proposal(85), { gate: 'submit' }));
    expect(ruled.ruling).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'default:required-screening-missing',
      evidence_refs: [{ kind: 'screening_skipped', reason: 'resolver-error' }],
    });
  });

  it('binds projection summaries and fixture signals into ruling evidence without allowing the signal', async () => {
    const h = harness();
    await initialize(h);
    const projectionRef = {
      kind: 'submit_projection' as const,
      provider: 'openai-gpt-5.5',
      role: 'screening' as const,
      included: 1,
      dropped: 0,
      dropped_item_ids: [],
      unmet_tags: [],
    };
    const signal = conflictSignal('Synthetic fixture conflict.');
    const core = new AuthorizationCore({
      store: h.store,
      keyring: h.keyring,
      policy: h.policy,
      systemUse: h.systemUse,
      ids: h.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveScreening: () => ({ performed: true, signals: [signal], evidenceRefs: [projectionRef] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'current',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const ruled = await core.ruleProposal(ruleInput(proposal(86), { gate: 'submit' }));
    expect(ruled.ruling).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'escalate-submit-signal',
      evidence_refs: [projectionRef, signal],
    });
  });

  it('authorizes a declared substitute role and records the actual responder', async () => {
    const h = harness();
    await initialize(h);
    const original = proposal(83);
    h.setScreening(original.proposal_id, [conflictSignal()]);
    const escalated = await h.core.ruleProposal(
      ruleInput(original, { gate: 'verify' }),
    );
    if (escalated.escalationId === null) throw new Error('expected escalation');
    const disposed = await h.core.disposeEscalation({
      escalationId: escalated.escalationId,
      disposition: 'deny',
      actor: PRINCIPAL,
    });
    expect(disposed).toMatchObject({ accepted: true });
    if (!disposed.accepted) throw new Error('expected substitute disposition');
    const event = h.store.snapshot().actionRecords.find((entry) => entry.entry_id === disposed.recordEntryId)
      ?.human_intervention_event;
    expect(event).toMatchObject({
      event: 'human_intervention_event',
      payload: { kind: 'disposition_recorded', responder_role: 'principal' },
    });
  });

  it('records a denied continuation without burning the next corrected revision', async () => {
    const h = harness();
    await initialize(h);
    const original = proposal(85);
    h.setScreening(original.proposal_id, [conflictSignal()]);
    const escalated = await h.core.ruleProposal(ruleInput(original, { gate: 'verify' }));
    if (escalated.escalationId === null) throw new Error('expected escalation');
    expect(
      await h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'narrow-or-modify',
        actor: CASE_OFFICER,
      }),
    ).toMatchObject({ accepted: true, successor: null });

    const deniedRevision = proposal(86, {
      action_id: original.action_id,
      revision: 2,
      target: { recipient: 'synthetic-other-recipient', resource: 'grant-decision' },
    });
    const denied = await h.core.continueEscalationRevision({
      escalationId: escalated.escalationId,
      proposal: deniedRevision,
      actor: ORCHESTRATOR,
    });
    expect(denied).toMatchObject({
      accepted: true,
      stages: [{ ruling: { gate: 'authorize', verdict: 'deny', matched_rule_id: 'authority:broadened-request' } }],
    });
    expect(h.store.snapshot().escalations.get(escalated.escalationId)?.successor_ruling_id).toBeNull();

    const correctedRevision = proposal(87, {
      action_id: original.action_id,
      revision: 3,
    });
    const corrected = await h.core.continueEscalationRevision({
      escalationId: escalated.escalationId,
      proposal: correctedRevision,
      actor: ORCHESTRATOR,
    });
    expect(corrected).toMatchObject({
      accepted: true,
      stages: [
        { ruling: { gate: 'authorize', verdict: 'allow' } },
        { ruling: { gate: 'submit', verdict: 'allow' } },
        { ruling: { gate: 'verify', verdict: 'allow' } },
      ],
    });
    if (!corrected.accepted) throw new Error('expected corrected continuation');
    expect(h.store.snapshot().escalations.get(escalated.escalationId)?.successor_ruling_id).toBe(
      corrected.successor.ruling.ruling_id,
    );
  });

  it('linearizes conflicting dispositions so exactly one reviewer transition wins', async () => {
    const h = harness();
    await initialize(h);
    const original = proposal(14);
    h.setScreening(original.proposal_id, [conflictSignal()]);
    const escalated = await h.core.ruleProposal(
      ruleInput(original, { gate: 'verify' }),
    );
    if (escalated.escalationId === null) throw new Error('expected escalation');
    const results = await Promise.all([
      h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'deny',
        actor: CASE_OFFICER,
      }),
      h.core.disposeEscalation({
        escalationId: escalated.escalationId,
        disposition: 'narrow-or-modify',
        actor: CASE_OFFICER,
      }),
    ]);
    expect(results.filter((result) => result.accepted)).toHaveLength(1);
    expect(results.filter((result) => !result.accepted)).toEqual([
      expect.objectContaining({ defect: 'late-disposition', terminalState: 'disposed' }),
    ]);
    expect(
      h.store.snapshot().actionRecords.some(
        (entry) => entry.human_intervention_event?.event === 'late_disposition_ignored',
      ),
    ).toBe(true);
  });

  it('re-rules allow within scope without letting human approval create a missing policy basis', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(16);
    const escalated = await h.core.ruleProposal(ruleInput(frozen, { gate: 'rely' }));
    expect(escalated.ruling).toMatchObject({ verdict: 'escalate', matched_rule_id: null });
    if (escalated.escalationId === null) throw new Error('expected escalation');

    const disposed = await h.core.disposeEscalation({
      escalationId: escalated.escalationId,
      disposition: 'allow-within-scope',
      actor: PRINCIPAL,
    });
    expect(disposed).toMatchObject({
      accepted: true,
      successor: { ruling: { verdict: 'escalate', matched_rule_id: null } },
    });
    if (!disposed.accepted || disposed.successor === null) throw new Error('expected successor');
    expect(h.store.snapshot().escalations.get(escalated.escalationId)).toMatchObject({
      state: 'disposed',
      successor_ruling_id: disposed.successor.ruling.ruling_id,
    });
    expect(disposed.successor.escalationId).not.toBeNull();
  });

  it('blocks a raw above-ceiling human approval at commitment verification', async () => {
    const h = harness();
    await initialize(h);
    const proposals = [172, 173, 174].map((sequence) =>
      proposal(sequence, {
        action_id: `act_aggregate_ceiling_${sequence}`,
        exact_parameters: { amount_minor_units: 40, reference: `case-aggregate-${sequence}` },
        cost_obligation: { amount_minor_units: 40, description: 'Synthetic cumulative amount.' },
      }),
    );
    const first = proposals[0];
    const second = proposals[1];
    const aboveCeiling = proposals[2];
    if (first === undefined || second === undefined || aboveCeiling === undefined) throw new Error('missing fixtures');
    expect((await h.core.ruleProposal(ruleInput(first))).ruling.verdict).toBe('allow');
    expect((await h.core.ruleProposal(ruleInput(second))).ruling.verdict).toBe('allow');
    const escalated = await h.core.ruleProposal(ruleInput(aboveCeiling));
    expect(escalated.ruling).toMatchObject({ verdict: 'escalate', matched_rule_id: 'default:aggregate-ceiling' });
    if (escalated.escalationId === null) throw new Error('expected aggregate-ceiling escalation');

    const attemptedApproval = await h.core.disposeEscalation({
      escalationId: escalated.escalationId,
      disposition: 'allow-within-scope',
      actor: PRINCIPAL,
    });
    expect(attemptedApproval).toMatchObject({ accepted: false, defect: 'disposition-not-permitted' });
    await expect(
      h.core.commitVerify({
        rulingId: escalated.ruling.ruling_id,
        intent: intentFor(aboveCeiling, escalated.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ).resolves.toEqual({ ok: false, defect: 'not-allowed' });
    expect(h.store.snapshot().commitments.size).toBe(0);
  });

  it('turns seek-review into a durable obligation without issuing effect authority', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(17);
    h.setScreening(frozen.proposal_id, [conflictSignal()]);
    const escalated = await h.core.ruleProposal(
      ruleInput(frozen, { gate: 'verify' }),
    );
    if (escalated.escalationId === null) throw new Error('expected escalation');
    const disposed = await h.core.disposeEscalation({
      escalationId: escalated.escalationId,
      disposition: 'seek-review',
      actor: CASE_OFFICER,
    });
    expect(disposed).toMatchObject({ accepted: true, successor: null });
    if (!disposed.accepted || disposed.reviewObligationId === null) throw new Error('expected review obligation');
    const state = h.store.snapshot();
    expect(state.reviews.get(disposed.reviewObligationId)).toMatchObject({
      state: 'open',
      route: 'review',
      source_entry_id: disposed.recordEntryId,
      recovery_owner_role: 'case_officer',
    });
    expect(state.actionRecords.find((entry) => entry.entry_id === disposed.recordEntryId)?.challenge_and_remedy).toEqual({
      route: 'review',
      opened_at: '2026-08-01T09:00:00.000Z',
    });
  });

  it('records an applicant correction and withdraws reliance into a single routed challenge obligation', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(171, { action_id: 'act_challenge' });
    const ruled = await h.core.ruleProposal(ruleInput(frozen, { gate: 'commit' }));
    expect(ruled.ruling.verdict).toBe('allow');
    const correctionText = 'The synthetic registration date is 2024-06-01, not 2023-06-01.';

    await expect(
      h.core.submitChallenge({
        actionId: frozen.action_id,
        contestedEntryId: ruled.recordEntryId,
        correctionText,
        actor: CASE_OFFICER,
      }),
    ).resolves.toMatchObject({ accepted: false, defect: 'wrong-role' });
    const other = proposal(175, { action_id: 'act_other_challenge' });
    const otherRuled = await h.core.ruleProposal(ruleInput(other, { gate: 'commit' }));
    expect(otherRuled.ruling.verdict).toBe('allow');
    await expect(
      h.core.submitChallenge({
        actionId: other.action_id,
        contestedEntryId: ruled.recordEntryId,
        correctionText,
        actor: APPLICANT,
      }),
    ).resolves.toMatchObject({ accepted: false, defect: 'entry-not-in-action' });

    const concurrent = await Promise.all([
      h.core.submitChallenge({
        actionId: frozen.action_id,
        contestedEntryId: ruled.recordEntryId,
        correctionText,
        actor: APPLICANT,
      }),
      h.core.submitChallenge({
        actionId: frozen.action_id,
        contestedEntryId: ruled.recordEntryId,
        correctionText,
        actor: APPLICANT,
      }),
    ]);
    const opened = concurrent.find((result) => result.accepted);
    const refused = concurrent.find((result) => !result.accepted);
    expect(opened).toMatchObject({ accepted: true, status: 'opened' });
    expect(refused).toMatchObject({ accepted: false, defect: 'already-open' });
    if (opened === undefined || !opened.accepted) throw new Error('expected challenge to open');
    const state = h.store.snapshot();
    expect(state.reviews.get(opened.reviewObligationId)).toMatchObject({
      case_id: frozen.action_id,
      source_entry_id: opened.recordEntryId,
      route: 'challenge',
      recovery_owner_role: 'principal',
      state: 'open',
    });
    expect(state.actionRecords.find((entry) => entry.entry_id === opened.recordEntryId)?.challenge_and_remedy).toEqual({
      route: 'challenge',
      opened_at: '2026-08-01T09:00:00.000Z',
      contested_entry_id: ruled.recordEntryId,
      correction_text: correctionText,
      reliance_state: 'withdrawn-pending-review',
      recovery_owner_role: 'principal',
    });
    expect(refused).toMatchObject({ reviewObligationId: opened.reviewObligationId });
  });

  it('escalates every cumulative ceiling before issuing unreserved allow authority', async () => {
    const amount = harness();
    await initialize(amount);
    const amountResults = [];
    for (let index = 50; index < 53; index += 1) {
      amountResults.push(
        await amount.core.ruleProposal(
          ruleInput(
            proposal(index, {
              cost_obligation: {
                amount_minor_units: 50,
                description: 'Synthetic amount.',
              },
            }),
          ),
        ),
      );
    }
    expect(amountResults.map((value) => value.ruling.verdict)).toEqual(['allow', 'allow', 'escalate']);
    expect(amountResults[2]?.ruling).toMatchObject({
      matched_rule_id: 'default:aggregate-ceiling',
      counter_reservations: [],
    });
    const ceilingEscalationId = amountResults[2]?.escalationId;
    if (ceilingEscalationId === null || ceilingEscalationId === undefined) {
      throw new Error('expected aggregate-ceiling escalation');
    }
    expect(
      amount.store.snapshot().escalations.get(ceilingEscalationId)?.contract.permitted_dispositions,
    ).not.toContain('allow-within-scope');
    expect(
      await amount.core.disposeEscalation({
        escalationId: ceilingEscalationId,
        disposition: 'allow-within-scope',
        actor: PRINCIPAL,
      }),
    ).toMatchObject({ accepted: false, defect: 'disposition-not-permitted', recordEntryId: expect.any(String) });
    expect(counterValue(amount.store.snapshot(), 'mdt_demo', 'amount')).toBe(100);

    const actions = harness();
    await initialize(
      actions,
      mandateBody({
        limits: { ...mandateBody().limits, amount_minor_units: 1_000, frequency_per_day: 2 },
      }),
    );
    const actionResults = [];
    for (let index = 60; index < 63; index += 1) {
      actionResults.push(
        await actions.core.ruleProposal(
          ruleInput(
            proposal(index, {
              cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
            }),
          ),
        ),
      );
    }
    expect(actionResults.map((value) => value.ruling.verdict)).toEqual(['allow', 'allow', 'escalate']);
    expect(actionResults[2]?.ruling.matched_rule_id).toBe('default:aggregate-ceiling');
    expect(counterValue(actions.store.snapshot(), 'mdt_demo', 'actions')).toBe(2);
  });

  it('serializes a counter race so only one request reserves below the ceiling', async () => {
    const h = harness();
    await initialize(
      h,
      mandateBody({
        action_class: 'notification',
        connected_service: 'notification',
        disclosure_destinations: ['notification'],
      }),
    );
    const first = proposal(10, {
      cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
      exact_parameters: { amount_minor_units: 0, reference: 'case-10', notification_volume: 3 },
      mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
    });
    const second = proposal(11, {
      cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
      exact_parameters: { amount_minor_units: 0, reference: 'case-11', notification_volume: 3 },
      mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
    });
    const results = await Promise.all([
      h.core.ruleProposal(
        ruleInput(first, {
          service: 'notification',
          actionClass: 'notification',
        }),
      ),
      h.core.ruleProposal(
        ruleInput(second, {
          service: 'notification',
          actionClass: 'notification',
        }),
      ),
    ]);
    expect(results.map((value) => value.ruling.verdict).sort()).toEqual(['allow', 'escalate']);
    expect(counterValue(h.store.snapshot(), 'mdt_demo', 'notification_volume')).toBe(3);
  });

  it('applies latest-version-wins and atomically invalidates rulings from the superseded mandate', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(15);
    const first = await h.core.ruleProposal(ruleInput(frozen));
    const amended = bindMandate(
      h.keyring,
      mandateBody({ version: 2, issued_at: '2026-08-01T09:00:01.000Z', user_objective: 'Amended objective.' }),
    );
    await h.core.amendMandate(amended, PRINCIPAL);
    const afterAmendment = h.store.snapshot();
    expect(afterAmendment.rulings.get(first.ruling.ruling_id)?.status).toBe('invalidated');
    for (const reservation of first.ruling.counter_reservations) {
      expect(afterAmendment.reservations.get(reservation.id)?.state).toBe('released');
    }
    const reruled = await h.core.ruleProposal(ruleInput(frozen));
    expect(reruled.ruling).toMatchObject({ verdict: 'deny' });
    expect(reruled.ruling.reason).toContain('invalid-mandate-binding');
  });

  it('blocks mutation after allow without consuming the ruling, then accepts only the exact frozen intent', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(16);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const exact = intentFor(frozen, ruled.ruling.ruling_id);
    const mutated = {
      ...exact,
      exact_parameters: { ...exact.exact_parameters, amount_minor_units: 99 },
    };
    expect(
      await h.core.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: mutated,
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ).toEqual({ ok: false, defect: 'proposal-mismatch' });
    expect(h.store.snapshot().rulings.get(ruled.ruling.ruling_id)?.status).toBe('issued');
    expect(
      (
        await h.core.commitVerify({
          rulingId: ruled.ruling.ruling_id,
          intent: exact,
          servicesHostBootId: 'services_boot_1',
          servicesLedgerId: SERVICES_LEDGER_ID,
          actor: SERVICES_HOST,
        })
      ).ok,
    ).toBe(true);
  });

  it('linearizes revocation before or after commit-verify with no interleaved third state', async () => {
    const revokeFirst = harness();
    await initialize(revokeFirst);
    const firstProposal = proposal(17);
    const firstRuling = await revokeFirst.core.ruleProposal(ruleInput(firstProposal));
    const [, denied] = await Promise.all([
      revokeFirst.core.revokeMandate('mdt_demo', 1, PRINCIPAL),
      revokeFirst.core.commitVerify({
        rulingId: firstRuling.ruling.ruling_id,
        intent: intentFor(firstProposal, firstRuling.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ]);
    expect(denied).toEqual({ ok: false, defect: 'replayed-ruling' });
    expect(revokeFirst.store.snapshot().commitments.size).toBe(0);

    const commitFirst = harness();
    await initialize(commitFirst);
    const secondProposal = proposal(18);
    const secondRuling = await commitFirst.core.ruleProposal(ruleInput(secondProposal));
    const [bound] = await Promise.all([
      commitFirst.core.commitVerify({
        rulingId: secondRuling.ruling.ruling_id,
        intent: intentFor(secondProposal, secondRuling.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
      commitFirst.core.revokeMandate('mdt_demo', 1, PRINCIPAL),
    ]);
    expect(bound.ok).toBe(true);
    expect([...commitFirst.store.snapshot().commitments.values()][0]?.state).toBe('bound');
    expect(commitFirst.store.snapshot().mandateStatus.get('mdt_demo')?.state).toBe('revoked');
  });

  it('linearizes a policy-content change before or after commit-verify', async () => {
    function changedPolicy(source: LoadedPolicy): LoadedPolicy {
      const policy = { ...source.policy, policy_version: '2026-08-01.2' };
      return { ...source, policy, policyContentDigest: digestFor('policy-set', policy) };
    }

    const reloadFirst = harness();
    await initialize(reloadFirst);
    const firstProposal = proposal(19);
    const firstRuling = await reloadFirst.core.ruleProposal(ruleInput(firstProposal));
    const [, denied] = await Promise.all([
      reloadFirst.core.reloadPolicy(changedPolicy(reloadFirst.policy), AUTHZ),
      reloadFirst.core.commitVerify({
        rulingId: firstRuling.ruling.ruling_id,
        intent: intentFor(firstProposal, firstRuling.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
    ]);
    expect(denied).toEqual({ ok: false, defect: 'replayed-ruling' });
    expect(reloadFirst.store.snapshot().commitments.size).toBe(0);

    const commitFirst = harness();
    await initialize(commitFirst);
    const secondProposal = proposal(20);
    const secondRuling = await commitFirst.core.ruleProposal(ruleInput(secondProposal));
    const [bound] = await Promise.all([
      commitFirst.core.commitVerify({
        rulingId: secondRuling.ruling.ruling_id,
        intent: intentFor(secondProposal, secondRuling.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        servicesLedgerId: SERVICES_LEDGER_ID,
        actor: SERVICES_HOST,
      }),
      commitFirst.core.reloadPolicy(changedPolicy(commitFirst.policy), AUTHZ),
    ]);
    expect(bound.ok).toBe(true);
    expect([...commitFirst.store.snapshot().commitments.values()][0]?.state).toBe('bound');
    expect(commitFirst.store.snapshot().policy?.policy_version).toBe('2026-08-01.2');
  });

  it('turns the recurring-escalation threshold into a suspended mandate version', async () => {
    const h = harness();
    await initialize(
      h,
      mandateBody({
        action_class: 'notification',
        connected_service: 'notification',
        disclosure_destinations: ['notification'],
      }),
    );
    const results = [];
    for (let index = 20; index < 23; index += 1) {
      results.push(
        await h.core.ruleProposal(
          ruleInput(
            proposal(index, {
              cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
              exact_parameters: { amount_minor_units: 0, reference: `case-${index}`, notification_volume: 6 },
            }),
            {
              service: 'notification',
              actionClass: 'notification',
            },
          ),
        ),
      );
    }
    expect(results.map((value) => value.ruling.verdict)).toEqual(['escalate', 'escalate', 'escalate']);
    expect(results[2]?.mandateNarrowed).toBe(true);
    const status = h.store.snapshot().mandateStatus.get('mdt_demo');
    expect(status).toMatchObject({ version: 2, state: 'suspended' });
    const narrowed = h.store.snapshot().mandates.get('mdt_demo@2');
    expect(narrowed).toBeDefined();
    expect(
      verifyEmbeddedMac(h.keyring, 'mandate-binding', narrowed as unknown as Record<string, unknown>, 'binding'),
    ).toBe('valid');
  });

  it('sweeps ruling expiry and escalation timeout and repairs a torn WAL tail on restart', async () => {
    const h = harness();
    await initialize(
      h,
      mandateBody({
        action_class: 'notification',
        connected_service: 'notification',
        disclosure_destinations: ['notification'],
      }),
    );
    const frozen = proposal(30, {
      cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
      exact_parameters: { amount_minor_units: 0, reference: 'case-30', notification_volume: 6 },
    });
    const ruled = await h.core.ruleProposal(
      ruleInput(frozen, {
        service: 'notification',
        actionClass: 'notification',
      }),
    );
    expect(ruled.ruling.verdict).toBe('escalate');
    h.setNow('2026-08-01T09:16:00.000Z');
    const swept = await runSweeper(h.store, h.keyring, h.policy, h.systemUse, h.ids);
    expect(swept).toMatchObject({ changed: true, expiredRulings: 1, timedOutEscalations: 1 });
    expect(h.store.snapshot().escalations.get(ruled.escalationId ?? '')?.state).toBe('timed_out');

    h.store.close();
    openStores.splice(openStores.indexOf(h.store), 1);
    appendFileSync(join(h.root, 'w-demo', 'wal.jsonl'), '{"partial":', 'utf8');
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_2',
      bootId: 'authz_boot_2',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.policy.evaluatorBuildDigest,
      now: () => '2026-08-01T09:17:00.000Z',
    });
    openStores.push(reopened);
    expect(verifyChain(join(h.root, 'w-demo', 'wal.jsonl'), 'wal-entry').ok).toBe(true);
    expect(reopened.snapshot().escalations.get(ruled.escalationId ?? '')?.state).toBe('timed_out');
  });

  it('rejects illegal lifecycle transitions and non-contiguous proposal revisions during replay', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(40);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const state = h.store.snapshot();

    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [{ op: 'ruling.consume', ruling_id: ruled.ruling.ruling_id }],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/consumed nonce/);
    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [{ op: 'reservation.settle', reservation_id: ruled.ruling.counter_reservations[0]?.id ?? '' }],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/consumed allow nonce/);

    const skipped = proposal(41, { action_id: frozen.action_id, revision: 3 });
    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [{ op: 'proposal.freeze', proposal: skipped }],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/must be revision 2/);

    const recorded = state.actionRecords[0];
    if (recorded === undefined) throw new Error('expected ruling record');
    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [
          {
            op: 'record.action.append',
            entry: { ...recorded, entry_id: 'rec_tampered', proposed_action: 'Different action.' },
          },
        ],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/differs from its ruling or proposal/);
  });

  it('keeps dialogue answers on the routed role path and makes bare third-party confirmation a recorded no-op', async () => {
    const evidenceLookups: RegistryEvidenceCitation[] = [];
    const h = harness('2026-08-01T09:00:00.000Z', {
      dialogue: true,
      resolveRegistryEvidence: (citation) => {
        evidenceLookups.push(citation);
        return citation.id === 'reg:CH-0042' && citation.retrieved_at === '2026-08-01T09:14:02.000Z'
          ? {
              kind: 'registry_record',
              id: citation.id,
              retrieved_at: citation.retrieved_at,
              resolved_at: '2026-08-01T09:15:00.000Z',
              content_digest: 'd'.repeat(64),
            }
          : null;
      },
    });
    await initialize(h, mandateBody(), 'case_dialogue');
    const inference = {
      id: 'inf_7',
      store: 'inferred' as const,
      turn: 'turn_dialogue',
      text: 'The synthetic applicant entity is no more than three years old.',
      provenance: { derived_from: ['said_3'], hops: [] },
      tags: ['conf:case', 'purpose:grant-assessment'],
    };
    const otherCaseInference = {
      ...inference,
      id: 'inf_other',
      text: 'A synthetic inference belonging to another case.',
    };
    await h.core.putConversationItems({ caseId: 'case_dialogue', items: [inference], actor: AUTHZ });
    await h.core.putConversationItems({ caseId: 'case_other', items: [otherCaseInference], actor: AUTHZ });
    const original = proposal(60, {
      action_id: 'act_dialogue',
      derived_claims: [inference, otherCaseInference],
    });
    await expect(
      h.core.ruleProposal(ruleInput(original, { context: { dialogue_trigger: true } })),
    ).rejects.toMatchObject({ code: 'dialogue-case-scope' });
    expect(h.store.snapshot().rulings.size).toBe(0);
    const ruled = await h.core.ruleProposal(
      ruleInput(original, { caseId: 'case_dialogue', context: { dialogue_trigger: true } }),
    );
    const escalationId = ruled.escalationId;
    if (escalationId === null) throw new Error('expected dialogue escalation');
    expect(ruled.ruling).toMatchObject({ verdict: 'escalate', ux_class: 'stop', status: 'issued' });
    expect(
      h.store.snapshot().actionRecords.find((entry) => entry.entry_id === ruled.recordEntryId)?.human_intervention_event,
    ).toMatchObject({
      payload: {
        kind: 'dialogue_trigger_raised',
        standing_class: 'third-party-fact',
        question_text: 'Can the applicant confirm the cited third-party registry fact?',
      },
    });

    await expect(
      h.core.disposeEscalation({ escalationId, disposition: 'confirm', actor: APPLICANT }),
    ).resolves.toMatchObject({ accepted: false, defect: 'disposition-not-permitted' });
    expect(h.store.snapshot().escalations.get(escalationId)?.state).toBe('open');

    const beforeCrossCase = h.store.snapshot().storeItems.size;
    await expect(
      h.core.respondDialogue({
        escalationId,
        disposition: 'correct',
        actor: APPLICANT,
        answerText: 'This correction must not cross a case boundary.',
        scope: { item_ref: 'inf_other', applies_to: 'this_case_only' },
      }),
    ).resolves.toMatchObject({ accepted: false, defect: 'invalid-response' });
    expect(h.store.snapshot().storeItems.size).toBe(beforeCrossCase);

    await expect(
      h.core.respondDialogue({
        escalationId,
        disposition: 'confirm',
        actor: CASE_OFFICER,
        evidenceRef: {
          kind: 'registry_record',
          id: 'reg:CH-0042',
          retrieved_at: '2026-08-01T09:14:02.000Z',
        },
      }),
    ).resolves.toMatchObject({ accepted: false, defect: 'wrong-role' });
    expect(evidenceLookups).toHaveLength(0);
    await expect(
      h.core.respondDialogue({
        escalationId,
        disposition: 'confirm',
        actor: APPLICANT,
        scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      }),
    ).resolves.toMatchObject({ accepted: false, defect: 'evidence-required' });
    await expect(
      h.core.respondDialogue({ escalationId, disposition: 'allow-within-scope', actor: APPLICANT }),
    ).resolves.toMatchObject({ accepted: false, defect: 'disposition-not-permitted' });
    expect(h.store.snapshot().escalations.get(escalationId)?.state).toBe('open');

    const answerText = 'The cited synthetic registry record supports the registration date.';
    const accepted = await h.core.respondDialogue({
      escalationId,
      disposition: 'confirm',
      actor: APPLICANT,
      answerText,
      scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      evidenceRef: {
        kind: 'registry_record',
        id: 'reg:CH-0042',
        retrieved_at: '2026-08-01T09:14:02.000Z',
      },
    });
    expect(accepted).toMatchObject({ accepted: true, status: 'disposed', reviewObligationId: null });
    expect(evidenceLookups).toHaveLength(1);
    const after = h.store.snapshot();
    expect(after.escalations.get(escalationId)).toMatchObject({
      state: 'disposed',
      terminal_disposition: 'confirm',
      successor_ruling_id: null,
    });
    expect(after.rulings.get(ruled.ruling.ruling_id)?.status).toBe('invalidated');
    const recorded = after.actionRecords.find(
      (entry) => entry.human_intervention_event?.event === 'human_intervention_event' &&
        entry.human_intervention_event.payload.kind === 'dialogue_response_recorded',
    );
    expect(recorded?.human_intervention_event).toMatchObject({
      payload: {
        kind: 'dialogue_response_recorded',
        disposition: 'confirm',
        responder_role: 'applicant',
        evidence_ref: { id: 'reg:CH-0042', content_digest: 'd'.repeat(64) },
        scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      },
    });
    expect(JSON.stringify(recorded)).not.toContain(answerText);
    const dialogueItems = [...after.storeItems.values()]
      .filter((entry) => entry.case_id === 'case_dialogue')
      .map((entry) => entry.item);
    expect(dialogueItems.filter((item) => item.store === 'said')).toEqual([
      expect.objectContaining({ text: answerText, origin_actor: 'applicant' }),
    ]);
    expect(dialogueItems.filter((item) => item.store === 'confirmed')).toEqual([
      expect.objectContaining({
        text: inference.text,
        origin_actor: 'applicant',
        tags: inference.tags,
      }),
    ]);

    await expect(
      h.core.respondDialogue({ escalationId, disposition: 'abstain', actor: APPLICANT }),
    ).resolves.toMatchObject({ accepted: false, defect: 'late-response', terminalState: 'disposed' });
    const { proposal_hash: ignoredHash, ...originalBody } = original;
    void ignoredHash;
    const revised = freezeProposal({
      ...originalBody,
      proposal_id: 'prp_dialogue_revision',
      revision: 2,
      proposed_action: 'Submit the revised filing after the recorded confirmation.',
    });
    const continued = await h.core.continueEscalationRevision({
      escalationId,
      proposal: revised,
      actor: ORCHESTRATOR,
    });
    expect(continued).toMatchObject({ accepted: false, defect: 'wrong-state' });
  });

  it.each([
    { disposition: 'correct' as const, sourceStore: 'inferred' as const, removesSource: true },
    { disposition: 'narrow' as const, sourceStore: 'inferred' as const, removesSource: true },
    { disposition: 'permit' as const, sourceStore: 'said' as const, removesSource: false },
  ])(
    'commits the $disposition conversation transition once and rejects its replay',
    async ({ disposition, sourceStore, removesSource }) => {
      const h = harness('2026-08-01T09:00:00.000Z', { dialogue: true });
      const caseId = `case_${disposition}`;
      await initialize(h, mandateBody(), caseId);
      const source = {
        id: `source_${disposition}`,
        store: sourceStore,
        turn: `turn_${disposition}`,
        text: `Synthetic source for ${disposition}.`,
        provenance: { derived_from: [], hops: [] },
        tags: ['conf:case', 'purpose:grant-assessment'],
        ...(sourceStore === 'inferred' ? {} : { origin_actor: 'applicant' as const }),
      };
      await h.core.putConversationItems({ caseId, items: [source], actor: AUTHZ });
      const ruled = await h.core.ruleProposal(
        ruleInput(
          proposal(disposition === 'correct' ? 63 : disposition === 'narrow' ? 64 : 65, {
            action_id: `act_${disposition}`,
            ...(sourceStore === 'inferred'
              ? { derived_claims: [source] }
              : { material_inputs: [source] }),
          }),
          { caseId, context: { dialogue_trigger: true } },
        ),
      );
      if (ruled.escalationId === null) throw new Error('expected dialogue escalation');
      const response = {
        escalationId: ruled.escalationId,
        disposition,
        actor: APPLICANT,
        answerText: `Synthetic ${disposition} response.`,
        scope: { item_ref: source.id, applies_to: 'this_case_only' as const },
      };
      await expect(h.core.respondDialogue(response)).resolves.toMatchObject({
        accepted: true,
        status: 'disposed',
      });
      const after = h.store.snapshot();
      expect(after.storeItems.has(source.id)).toBe(!removesSource);
      const transitioned = [...after.storeItems.values()]
        .filter((entry) => entry.case_id === caseId && entry.item.id !== source.id)
        .map((entry) => entry.item);
      expect(transitioned.filter((item) => item.store === 'said')).toEqual([
        expect.objectContaining({
          text: response.answerText,
          tags: source.tags,
          origin_actor: 'applicant',
        }),
      ]);
      expect(transitioned.filter((item) => item.store === 'permitted')).toHaveLength(
        disposition === 'permit' ? 1 : 0,
      );

      const storeCount = after.storeItems.size;
      await expect(h.core.respondDialogue(response)).resolves.toMatchObject({
        accepted: false,
        defect: 'late-response',
        terminalState: 'disposed',
      });
      expect(h.store.snapshot().storeItems.size).toBe(storeCount);
    },
  );

  it('reopens a historical scope-less dialogue record without changing its materialized projection', async () => {
    const h = harness('2026-08-01T09:00:00.000Z', { dialogue: true });
    await initialize(h, mandateBody(), 'case_legacy');
    const inference = {
      id: 'inf_legacy',
      store: 'inferred' as const,
      turn: 'turn_legacy',
      text: 'Synthetic historical inference.',
      provenance: { derived_from: [], hops: [] },
      tags: ['conf:case', 'purpose:grant-assessment'],
    };
    await h.core.putConversationItems({ caseId: 'case_legacy', items: [inference], actor: AUTHZ });
    const ruled = await h.core.ruleProposal(
      ruleInput(proposal(66, { action_id: 'act_legacy', derived_claims: [inference] }), {
        caseId: 'case_legacy',
        context: { dialogue_trigger: true },
      }),
    );
    if (ruled.escalationId === null) throw new Error('expected dialogue escalation');
    const basis = h.store.snapshot().actionRecords.find((entry) => entry.entry_id === ruled.recordEntryId);
    if (basis === undefined) throw new Error('expected ruling record');
    const legacy = recordEntry.parse({
      ...basis,
      entry_id: 'rec_legacy_scope_less',
      authenticated_actor: APPLICANT.credential,
      claimed_actor: { role: 'applicant' },
      human_intervention_event: {
        event: 'human_intervention_event',
        escalation_id: ruled.escalationId,
        payload: {
          kind: 'dialogue_response_recorded',
          disposition: 'confirm',
          responder_role: 'applicant',
          evidence_ref: null,
          answer_digest: null,
        },
      },
    });
    await h.store.transact('legacy_dialogue_record', AUTHZ, [{ op: 'record.action.append', entry: legacy }]);

    h.store.close();
    openStores.splice(openStores.indexOf(h.store), 1);
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_2',
      bootId: 'authz_boot_2',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.policy.evaluatorBuildDigest,
      now: () => '2026-08-01T09:01:00.000Z',
    });
    openStores.push(reopened);
    const replayed = reopened.snapshot().actionRecords.find((entry) => entry.entry_id === legacy.entry_id);
    if (
      replayed?.human_intervention_event?.event !== 'human_intervention_event' ||
      replayed.human_intervention_event.payload.kind !== 'dialogue_response_recorded'
    ) {
      throw new Error('expected replayed historical dialogue response');
    }
    expect(replayed.human_intervention_event.payload.scope).toBeUndefined();
  });

  it('enforces dialogue response status codes and raw-client bypass resistance on a real listener', async () => {
    const h = harness('2026-08-01T09:00:00.000Z', {
      dialogue: true,
      resolveRegistryEvidence: (citation) =>
        citation.id === 'reg:CH-0042' && citation.retrieved_at === '2026-08-01T09:14:02.000Z'
          ? {
              kind: 'registry_record',
              id: citation.id,
              retrieved_at: citation.retrieved_at,
              resolved_at: '2026-08-01T09:15:00.000Z',
              content_digest: 'd'.repeat(64),
            }
          : null,
    });
    await initialize(h, mandateBody(), 'case_dialogue_http');
    const inference = {
      id: 'inf_7',
      store: 'inferred' as const,
      turn: 'turn_dialogue_http',
      text: 'The synthetic applicant entity is no more than three years old.',
      provenance: { derived_from: ['said_3'], hops: [] },
      tags: ['conf:case', 'purpose:grant-assessment'],
    };
    await h.core.putConversationItems({ caseId: 'case_dialogue_http', items: [inference], actor: AUTHZ });
    const ruled = await h.core.ruleProposal(
      ruleInput(proposal(61, { action_id: 'act_dialogue_http', derived_claims: [inference] }), {
        caseId: 'case_dialogue_http',
        context: { dialogue_trigger: true },
      }),
    );
    const escalationId = ruled.escalationId;
    if (escalationId === null) throw new Error('expected dialogue escalation');
    const tokens = {
      principal: '1'.repeat(64),
      caseOfficer: '2'.repeat(64),
      applicant: '3'.repeat(64),
      orchestrator: '4'.repeat(64),
      services: '5'.repeat(64),
    };
    const adapter = new AuthorizationHttpAdapter({
      authorization: h.core,
      ownOrigin: 'http://127.0.0.1:7801',
      demoWorldId: 'w-demo',
      credentials: [
        { label: 'role:principal', token: tokens.principal, worldId: 'w-demo' },
        { label: 'role:case_officer', token: tokens.caseOfficer, worldId: 'w-demo' },
        { label: 'role:applicant', token: tokens.applicant, worldId: 'w-demo' },
        { label: 'proc:orchestrator', token: tokens.orchestrator, worldId: 'w-demo' },
        { label: 'proc:services_host', token: tokens.services, worldId: 'w-demo' },
      ],
    });
    const server = new AuthorizationHttpServer({
      authorization: h.core,
      conversationProjections: {} as ConversationProjectionService,
      conversationTransport: {} as ConversationTransportService,
      reads: {} as AuthorizationReadSide,
      adapter,
      keyring: h.keyring,
      caseHandoffs: {} as CaseSessionHandoffService,
      systemUse: h.systemUse,
      runtimeConfig: {
        authorization_origin: 'http://127.0.0.1:7801',
        orchestrator_origin: 'http://127.0.0.1:7802',
      },
      consoleAssets: { shell: '', script: '', stylesheet: '' },
      caseId: 'case_dialogue_http',
      host: '127.0.0.1',
      port: 0,
    });
    const address = await server.listen();
    const post = (token: string, body: unknown, origin?: string) =>
      fetch(`${address.origin}/w/w-demo/escalations/${escalationId}/response`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          ...(origin === undefined ? {} : { origin }),
        },
        body: JSON.stringify(body),
      });
    const baseBody = {
      escalation_id: escalationId,
      disposition: 'confirm',
      scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
    };
    try {
      const legacyDispositionBypass = await fetch(
        `${address.origin}/w/w-demo/escalations/${escalationId}/disposition`,
        {
          method: 'POST',
          headers: {
            authorization: `Bearer ${tokens.caseOfficer}`,
            'content-type': 'application/json',
          },
          body: JSON.stringify({ disposition: 'confirm' }),
        },
      );
      expect(legacyDispositionBypass.status).toBe(422);
      await expect(legacyDispositionBypass.json()).resolves.toEqual({ error: 'invalid-request' });
      expect(h.store.snapshot().escalations.get(escalationId)?.state).toBe('open');

      const processBypass = await post(tokens.orchestrator, baseBody);
      expect(processBypass.status).toBe(403);
      const foreignOrigin = await post(tokens.applicant, baseBody, 'http://127.0.0.1:9999');
      expect(foreignOrigin.status).toBe(403);
      const wrongRole = await post(tokens.caseOfficer, baseBody);
      expect(wrongRole.status).toBe(403);
      await expect(wrongRole.json()).resolves.toMatchObject({ accepted: false, defect: 'wrong-role' });
      const bareConfirm = await post(tokens.applicant, baseBody);
      expect(bareConfirm.status).toBe(422);
      await expect(bareConfirm.json()).resolves.toMatchObject({ accepted: false, defect: 'evidence-required' });
      const accepted = await post(tokens.applicant, {
        ...baseBody,
        answer_text: 'The cited synthetic record supports the date.',
        evidence_ref: {
          kind: 'registry_record',
          id: 'reg:CH-0042',
          retrieved_at: '2026-08-01T09:14:02.000Z',
        },
      });
      expect(accepted.status).toBe(200);
      const replay = await post(tokens.applicant, { escalation_id: escalationId, disposition: 'abstain' });
      expect(replay.status).toBe(409);
      await expect(replay.json()).resolves.toMatchObject({
        accepted: false,
        defect: 'late-response',
        terminalState: 'disposed',
      });
    } finally {
      await server.close();
    }
    expect(
      h.store.snapshot().accessRecords.some(
        (entry) =>
          'route' in entry &&
          entry.route === 'POST /w/{world_id}/escalations/{id}/response' &&
          entry.authenticated_actor === 'proc:orchestrator' &&
          entry.outcome === 'forbidden',
      ),
    ).toBe(true);
  });
});
