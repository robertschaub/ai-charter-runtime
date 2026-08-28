// SPDX-License-Identifier: MIT
import { mkdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  AuthorizationCore,
  bindMandate,
  CaseSessionHandoffService,
  CardRegistry,
  ConversationProjectionService,
  digestFor,
  ExecutionPreparationService,
  freezeProposal,
  Keyring,
  loadPolicyFile,
  ProposalIntakeService,
  ProposalPrecommitService,
  type LoadedPolicy,
  syntheticSystemUseForTests,
  type SystemUseDecisionService,
  WalStore,
  type EffectIntent,
  type FrozenProposal,
  type Gate,
  type IdFactory,
  type Mandate,
  type ScreeningSignal,
} from 'gate-core/offline-safe';
import { EffectLedger, MockServicesHost } from 'services-mock/offline-safe';

import { REPOSITORY_ROOT } from './repository.js';
import type { CardBinding, LaneSlot } from './types.js';

const POLICY_PATH = join(REPOSITORY_ROOT, 'packages', 'gate-core', 'policy', 'v1.yaml');
const CARD_PATH = join(REPOSITORY_ROOT, 'docs', 'cards');
const MANDATE_PATH = join(REPOSITORY_ROOT, 'fixtures', 'demo', 'mandate.json');
const KEY_ID = 'm6-offline-hmac';
const KEY = 'a'.repeat(64);
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const CASE_OFFICER = { credential: 'role:case_officer', claimed_role: 'case_officer' } as const;
const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: null } as const;
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;
const SERVICES_HOST = { credential: 'proc:services_host', claimed_role: null } as const;

class DeterministicIds implements IdFactory {
  #next = 0;
  constructor(readonly prefix: string) {}
  next(kind: Parameters<IdFactory['next']>[0]): string {
    this.#next += 1;
    return `${kind}_${this.prefix}_${this.#next}`;
  }
}

function safeId(value: string): string {
  return value.replaceAll('-', '_').replaceAll('.', '_');
}

export interface ProductionHarnessOptions {
  readonly recordsRoot: string;
  readonly caseId: string;
  readonly laneSlot: LaneSlot;
  readonly selectedCard: CardBinding;
  readonly now?: string;
  readonly mandateOverrides?: Partial<Omit<Mandate, 'binding'>>;
}

export class ProductionHarness {
  readonly store: WalStore;
  readonly core: AuthorizationCore;
  readonly keyring: Keyring;
  readonly cards: CardRegistry;
  readonly policy: LoadedPolicy;
  readonly mandate: Mandate;
  readonly selectionId: string;
  readonly caseId: string;
  readonly laneSlot: LaneSlot;
  readonly selectedCard: CardBinding;
  readonly systemUse: SystemUseDecisionService;
  readonly authorizationBootId: string;
  readonly sessionId: string;
  readonly conversationProjections: ConversationProjectionService;
  readonly proposalIntakes: ProposalIntakeService;
  readonly proposalPrecommit: ProposalPrecommitService;
  readonly executionPreparations: ExecutionPreparationService;
  readonly #getNow: () => string;
  readonly #setNow: (value: string) => void;
  readonly #signals = new Map<'submit' | 'verify', readonly ScreeningSignal[]>();
  #proposalSequence = 0;
  #nativeContextReady = false;

  private constructor(options: ProductionHarnessOptions, store: WalStore, core: AuthorizationCore, keyring: Keyring, cards: CardRegistry, policy: LoadedPolicy, mandate: Mandate, selectionId: string, systemUse: SystemUseDecisionService, authorizationBootId: string, getNow: () => string, setNow: (value: string) => void) {
    this.store = store;
    this.core = core;
    this.keyring = keyring;
    this.cards = cards;
    this.policy = policy;
    this.mandate = mandate;
    this.selectionId = selectionId;
    this.caseId = options.caseId;
    this.laneSlot = options.laneSlot;
    this.selectedCard = options.selectedCard;
    this.systemUse = systemUse;
    this.authorizationBootId = authorizationBootId;
    this.sessionId = `session_${safeId(options.caseId)}_${safeId(options.laneSlot)}`;
    this.#getNow = getNow;
    this.#setNow = setNow;
    let intakeSequence = 0;
    let proposalSequence = 0;
    let actionSequence = 0;
    let executionPreparationSequence = 0;
    this.proposalIntakes = new ProposalIntakeService({
      store,
      cards,
      keyring,
      systemUse,
      caseId: safeId(options.caseId),
      authorizationBootId,
      now: getNow,
      nextIntakeId: () => `pint_${safeId(options.caseId)}_${safeId(options.laneSlot)}_${++intakeSequence}`,
      nextProposalId: () => `prp_native_${safeId(options.caseId)}_${safeId(options.laneSlot)}_${++proposalSequence}`,
      nextActionId: () => `act_native_${safeId(options.caseId)}_${safeId(options.laneSlot)}_${++actionSequence}`,
    });
    this.conversationProjections = new ConversationProjectionService({
      store,
      cards,
      keyring,
      caseId: safeId(options.caseId),
      authorizationBootId,
      screeningFixtures: [],
      systemUse,
      proposalIntakes: this.proposalIntakes,
      now: getNow,
    });
    this.proposalPrecommit = new ProposalPrecommitService({
      store,
      authorization: core,
      proposalIntakes: this.proposalIntakes,
      now: getNow,
    });
    this.executionPreparations = new ExecutionPreparationService({
      store,
      authorization: core,
      proposalIntakes: this.proposalIntakes,
      authorizationBootId,
      authorizedAgentId: 'agent_demo',
      now: getNow,
      nextId: () => `xpr_${safeId(options.caseId)}_${safeId(options.laneSlot)}_${++executionPreparationSequence}`,
    });
  }

  static async create(options: ProductionHarnessOptions): Promise<ProductionHarness> {
    mkdirSync(options.recordsRoot, { recursive: true });
    let now = options.now ?? '2026-08-01T09:00:00.000Z';
    const caseId = safeId(options.caseId);
    const lane = safeId(options.laneSlot);
    const buildDigest = digestFor('evaluator-build', { package: 'm6-offline', case_id: options.caseId, lane: options.laneSlot });
    const policy = loadPolicyFile(POLICY_PATH, buildDigest);
    const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
    const authorizationBootId = `authz_boot_${caseId}_${lane}`;
    const store = WalStore.open({
      recordsRoot: options.recordsRoot,
      worldId: 'w-demo',
      runId: `run_${caseId}_${lane}`,
      bootId: authorizationBootId,
      policyVersion: policy.policy.policy_version,
      policyContentDigest: policy.policyContentDigest,
      evaluatorBuildDigest: buildDigest,
      now: () => now,
    });
    const cards = CardRegistry.load(CARD_PATH);
    const systemUse = syntheticSystemUseForTests(store);
    let harness: ProductionHarness | undefined;
    const core = new AuthorizationCore({
      store,
      keyring,
      policy,
      systemUse,
      ids: new DeterministicIds(`${caseId}_${lane}`),
      resolveAuthorizedAgent: (actor) => actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined,
      resolveModelEvidence: (proposal) => cards.resolve(proposal),
      resolveRegistryEvidence: (citation) => citation.id === 'reg:CH-0042'
        ? {
            kind: 'registry_record', id: citation.id, retrieved_at: citation.retrieved_at,
            resolved_at: now, content_digest: 'd'.repeat(64),
          }
        : null,
      resolveScreening: (_proposal, gate) => ({
        performed: true,
        signals: harness === undefined ? [] : (harness.#signals.get(gate) ?? []),
        evidenceRefs: [],
      }),
      validateScreeningResolution: () => true,
    });
    await core.activatePolicy();
    const mandateBody = JSON.parse(readFileSync(MANDATE_PATH, 'utf8')) as Omit<Mandate, 'binding'>;
    const selectedDefault = {
      card_id: options.selectedCard.card_id,
      card_version: options.selectedCard.card_version,
      requested_id: options.selectedCard.requested_id,
    };
    const mandate = bindMandate(keyring, {
      ...mandateBody,
      default_acting_model: selectedDefault,
      ...options.mandateOverrides,
    });
    await core.grantMandate(mandate, PRINCIPAL);
    const selectionId = `sel_${caseId}_${lane}`;
    const inspection = cards.get(options.selectedCard.card_id);
    if (inspection === undefined || !inspection.signatureValid || inspection.digest !== options.selectedCard.card_digest) {
      store.close();
      throw new Error(`selected card ${options.selectedCard.card_id} is not the exact verified binding`);
    }
    const policyActivation = store.snapshot().policy;
    if (policyActivation === undefined) {
      store.close();
      throw new Error('policy activation did not materialize');
    }
    const systemUseBinding = systemUse.resolve(store.snapshot(), mandate, policyActivation.policy_version, now);
    const checkId = `msc_${caseId}_${lane}`;
    const target = {
      ...selectedDefault,
      card_digest: options.selectedCard.card_digest,
      verifying_key_id: inspection.keyId,
    };
    await store.transact('m6_model_selection_check', ORCHESTRATOR, [{
      op: 'model_selection_check.issue',
      check: {
        kind: 'model_selection_check',
        world_id: 'w-demo',
        check_id: checkId,
        authorization_boot_id: authorizationBootId,
        case_id: caseId,
        authenticated_actor: 'proc:orchestrator',
        expected_current_selection_id: null,
        mandate_id: mandate.mandate_id,
        mandate_version: mandate.version,
        target,
        system_use_decision: systemUseBinding,
        policy_version: policyActivation.policy_version,
        policy_content_digest: policyActivation.policy_content_digest,
        evaluator_build_id: policyActivation.evaluator_build_id,
        issued_at: now,
        expires_at: new Date(Date.parse(now) + 300_000).toISOString(),
        state: 'issued',
        consumed_at: null,
      },
    }], now);
    await store.transact('m6_model_selection_apply', ORCHESTRATOR, [
      { op: 'model_selection_check.consume', check_id: checkId, consumed_at: now },
      {
        op: 'model_selection.append',
        selection: {
          world_id: 'w-demo',
          selection_id: selectionId,
          case_id: caseId,
          kind: 'initial',
          predecessor_selection_id: null,
          mandate_id: mandate.mandate_id,
          mandate_version: mandate.version,
          target,
          system_use_decision: systemUseBinding,
          check_id: checkId,
          selected_at: now,
          authority_effect: 'none',
        },
      },
    ], now);
    harness = new ProductionHarness(options, store, core, keyring, cards, policy, mandate, selectionId, systemUse, authorizationBootId, () => now, (value) => { now = value; });
    return harness;
  }

  get now(): string {
    return this.#getNow();
  }

  setNow(value: string): void {
    this.#setNow(value);
  }

  projections(): ConversationProjectionService {
    return this.conversationProjections;
  }

  async prepareNativeContext(): Promise<void> {
    if (this.#nativeContextReady) return;
    const caseId = safeId(this.caseId);
    const handoffs = new CaseSessionHandoffService({
      store: this.store,
      worldId: 'w-demo',
      authorizationBootId: this.authorizationBootId,
      targetOrigin: 'http://127.0.0.1:7802',
      caseExists: (candidate) => candidate === caseId,
      randomCode: () => 'b'.repeat(64),
      nextHandoffId: () => `handoff_${caseId}_${safeId(this.laneSlot)}`,
    });
    const minted = await handoffs.mint(caseId, CASE_OFFICER);
    const { expires_at: ignoredExpiry, ...input } = minted;
    void ignoredExpiry;
    await handoffs.redeem({ ...input, session_id: this.sessionId }, ORCHESTRATOR);
    await this.core.putConversationItems({
      caseId,
      actor: AUTHZ,
      items: [{
        id: `said_${caseId}_${safeId(this.laneSlot)}`,
        store: 'said',
        turn: `turn_${caseId}`,
        text: 'Synthetic applicant filing facts.',
        provenance: { derived_from: [], hops: [] },
        tags: ['conf:case', 'purpose:grant-assessment'],
        origin_actor: 'applicant',
      }],
    });
    this.#nativeContextReady = true;
  }

  setSignals(gate: 'submit' | 'verify', signals: readonly ScreeningSignal[]): void {
    this.#signals.set(gate, signals);
  }

  proposal(overrides: Partial<Omit<FrozenProposal, 'proposal_hash'>> = {}): FrozenProposal {
    this.#proposalSequence += 1;
    const sequence = this.#proposalSequence;
    return freezeProposal({
      world_id: 'w-demo',
      proposal_id: `prp_${safeId(this.caseId)}_${safeId(this.laneSlot)}_${sequence}`,
      revision: 1,
      action_id: `act_${safeId(this.caseId)}_${safeId(this.laneSlot)}_${sequence}`,
      selection_id: this.selectionId,
      created_at: this.now,
      declared_objective: 'File the synthetic grant.',
      proposed_action: 'Submit the synthetic grant filing.',
      target: { recipient: 'grant-office', resource: 'application-42' },
      exact_parameters: { amount_minor_units: 50, reference: `synthetic-${sequence}` },
      material_inputs: [],
      derived_claims: [],
      data_to_be_disclosed: ['applicant_name'],
      cost_obligation: { amount_minor_units: 50, description: 'Synthetic amount.' },
      material_consequences: ['Synthetic public-funds commitment.'],
      reversibility_class: 'partially-reversible',
      commercial_influence: { applicable: false, note: 'Not applicable in the synthetic scenario.' },
      acting_model: {
        requested_id: this.selectedCard.requested_id,
        served_id: this.selectedCard.requested_id,
        card_id: this.selectedCard.card_id,
        card_version: this.selectedCard.card_version,
      },
      mandate_ref: { mandate_id: this.mandate.mandate_id, version: this.mandate.version },
      ...overrides,
    });
  }

  async rule(gate: Gate, proposal: FrozenProposal, context: Readonly<Record<string, unknown>> = {}) {
    return this.core.ruleProposal({
      gate,
      proposal,
      service: this.mandate.connected_service,
      actionClass: this.mandate.action_class,
      actor: ORCHESTRATOR,
      caseId: safeId(this.caseId),
      context,
    });
  }

  intent(proposal: FrozenProposal, rulingId: string, overrides: Partial<EffectIntent> = {}): EffectIntent {
    return {
      world_id: proposal.world_id,
      ruling_id: rulingId,
      frozen_proposal_hash: proposal.proposal_hash,
      service: this.mandate.connected_service,
      action_class: this.mandate.action_class,
      target: proposal.target,
      exact_parameters: proposal.exact_parameters,
      data_to_be_disclosed: proposal.data_to_be_disclosed,
      ...overrides,
    };
  }

  services(recordsRoot: string): MockServicesHost {
    const ledger = new EffectLedger({
      recordsRoot,
      worldId: 'w-demo',
      bootId: `services_boot_${safeId(this.caseId)}_${safeId(this.laneSlot)}`,
      keyring: this.keyring,
      now: () => this.now,
    });
    return new MockServicesHost(ledger, this.core);
  }

  nativeServices(recordsRoot: string): MockServicesHost {
    const ledger = new EffectLedger({
      recordsRoot,
      worldId: 'w-demo',
      bootId: `services_boot_${safeId(this.caseId)}_${safeId(this.laneSlot)}`,
      keyring: this.keyring,
      now: () => this.now,
    });
    return new MockServicesHost(ledger, {
      commitVerify: (input) => this.core.commitVerify(input),
      reportEffectOutcome: (input) => this.core.reportEffectOutcome(input),
      commitVerifyPreparation: (_worldId, preparationId, servicesHostBootId, servicesLedgerId) =>
        this.executionPreparations.commitVerify(preparationId, servicesHostBootId, servicesLedgerId, SERVICES_HOST),
    });
  }

  close(): void {
    this.store.close();
  }
}
