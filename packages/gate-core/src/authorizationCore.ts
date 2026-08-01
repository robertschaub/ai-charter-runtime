// SPDX-License-Identifier: AGPL-3.0-only
/** Atomic M2 authorization transactions built on the replay-complete WAL. */
import { randomUUID } from 'node:crypto';

import { canonicalize } from './canonicalize.js';
import { evaluatePolicy, escalationPatternRequiresNarrowing, type AuthorityDefect } from './evaluator.js';
import { digestFor, sha256Hex, verifyDigest } from './hash.js';
import { createEmbeddedMac, type Keyring, verifyEmbeddedMac } from './keyring.js';
import {
  frozenProposal,
  gateRuling,
  commitToken,
  effectIntent,
  type CommitToken,
  mandate,
  type CounterName,
  type EvidenceRef,
  type EffectIntent,
  type FrozenProposal,
  type Gate,
  type GateRuling,
  type InterventionContract,
  type Mandate,
  type PatternEvent,
  type RecordEntry,
  type ScreeningSignal,
  type WalOp,
} from './schemas/index.js';
import { counterValue, mandateVersionKey, type WorldState } from './state.js';
import type { LoadedPolicy } from './policyLoader.js';
import { WalStore, type TransactionActor } from './walStore.js';

const ZERO_DIGEST = '0'.repeat(64);

export class AuthorizationError extends Error {
  constructor(
    readonly code:
      | 'invalid-mandate-mac'
      | 'proposal-hash'
      | 'proposal-conflict'
      | 'policy-not-active'
      | 'invalid-counter-delta'
      | 'unsupported-ordering-rule',
    message: string,
  ) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

export interface IdFactory {
  next(prefix: 'rul' | 'nce' | 'rsv' | 'esc' | 'pat' | 'rec' | 'cmt' | 'eff'): string;
}

const defaultIds: IdFactory = {
  next: (prefix) => `${prefix}_${randomUUID()}`,
};

export interface AuthorizationCoreOptions {
  readonly store: WalStore;
  readonly keyring: Keyring;
  readonly policy: LoadedPolicy;
  readonly rulingTtlMs?: number;
  readonly commitTokenTtlMs?: number;
  readonly ids?: IdFactory;
  /** Server-owned credential mapping; never take the agent id from the model request body. */
  readonly resolveAuthorizedAgent: (actor: TransactionActor) => string | undefined;
  /** Server-owned signed-card lookup; the orchestrator cannot attest its own model. */
  readonly resolveModelEvidence: (proposal: FrozenProposal) => ModelEvidence;
}

export interface ModelEvidence {
  /** Result of the signed-card served-model comparison performed before the lock. */
  readonly servedModelAccepted: boolean;
  readonly cardStatus: 'current' | 'superseded' | 'withdrawn';
  readonly cardKeyId: string;
  readonly cardDigest: string;
}

export interface RuleProposalInput {
  readonly gate: Gate;
  readonly proposal: FrozenProposal;
  readonly service: string;
  readonly actionClass: string;
  readonly actor: TransactionActor;
  /** Authorization-service classifications only; endpoint code must not pass model-authored labels through. */
  readonly context?: Readonly<Record<string, unknown>>;
  /** Screening-client evidence gathered by the authorization service over this frozen hash. */
  readonly signals?: readonly ScreeningSignal[];
  readonly screeningPerformed?: boolean;
}

export interface RuleProposalResult {
  readonly ruling: GateRuling;
  readonly escalationId: string | null;
  readonly recordEntryId: string;
  readonly mandateNarrowed: boolean;
}

export type CommitDefect = AuthorityDefect | 'not-allowed' | 'counter-invalid' | 'expired-ruling';

export type CommitVerifyResult =
  | {
      readonly ok: true;
      readonly token: CommitToken;
      readonly commitmentId: string;
      readonly recordEntryId: string;
    }
  | { readonly ok: false; readonly defect: CommitDefect };

export interface CommitVerifyInput {
  readonly rulingId: string;
  readonly intent: EffectIntent;
  readonly servicesHostBootId: string;
  readonly actor: TransactionActor;
  readonly recoveryOwnerRole?: 'principal' | 'case_officer' | 'applicant';
}

export type FrozenProposalBody = Omit<FrozenProposal, 'proposal_hash'>;

export function freezeProposal(body: FrozenProposalBody): FrozenProposal {
  const parsedBody = frozenProposal.omit({ proposal_hash: true }).parse(body);
  return frozenProposal.parse({ ...parsedBody, proposal_hash: digestFor('proposal', parsedBody) });
}

function verifyProposalHash(proposal: FrozenProposal): void {
  const { proposal_hash: expected, ...body } = proposal;
  if (!verifyDigest(expected, digestFor('proposal', body))) {
    throw new AuthorizationError('proposal-hash', `proposal ${proposal.proposal_id} has an invalid frozen hash`);
  }
}

export function bindMandate(keyring: Keyring, body: Omit<Mandate, 'binding'>): Mandate {
  return mandate.parse(createEmbeddedMac(keyring, 'mandate-binding', body, 'binding'));
}

function mandateBody(value: Mandate): Omit<Mandate, 'binding'> {
  const { binding: ignored, ...body } = value;
  void ignored;
  return body;
}

function requireValidMandateMac(keyring: Keyring, value: Mandate): void {
  if (verifyEmbeddedMac(keyring, 'mandate-binding', value as unknown as Record<string, unknown>, 'binding') !== 'valid') {
    throw new AuthorizationError('invalid-mandate-mac', `mandate ${value.mandate_id}@${value.version} is not validly bound`);
  }
}

function addMilliseconds(timestamp: string, milliseconds: number): string {
  const value = Date.parse(timestamp) + milliseconds;
  if (!Number.isSafeInteger(value)) throw new RangeError('timestamp arithmetic left the safe-integer regime');
  return new Date(value).toISOString();
}

function unique<T>(values: readonly T[]): T[] {
  return [...new Set(values)];
}

function equalTarget(left: FrozenProposal['target'], right: Mandate['target']): boolean {
  return left.recipient === right.recipient && left.resource === right.resource;
}

function activeMandateForProposal(state: WorldState, proposal: FrozenProposal): Mandate | undefined {
  const status = state.mandateStatus.get(proposal.mandate_ref.mandate_id);
  if (status === undefined) return undefined;
  return state.mandates.get(mandateVersionKey(proposal.mandate_ref.mandate_id, status.version));
}

function authorityDefects(
  state: WorldState,
  input: RuleProposalInput,
  policy: LoadedPolicy,
  keyring: Keyring,
  now: string,
  authorizedAgentId: string | undefined,
  modelEvidence: ModelEvidence,
): {
  defects: AuthorityDefect[];
  mandate: Mandate | undefined;
  cardDigest: string;
  cardKeyId: string;
  reauthorizationRequired: boolean;
} {
  const defects: AuthorityDefect[] = [];
  const status = state.mandateStatus.get(input.proposal.mandate_ref.mandate_id);
  const current = activeMandateForProposal(state, input.proposal);
  if (status === undefined || current === undefined) {
    defects.push('missing-mandate');
  } else {
    if (status.version !== input.proposal.mandate_ref.version) defects.push('invalid-mandate-binding');
    if (status.state === 'revoked') defects.push('revoked-mandate');
    if (status.state === 'suspended') defects.push('suspended-mandate');
    if (status.state === 'expired' || now > current.expires_at || now > current.limits.time_window.not_after) {
      defects.push('expired-mandate');
    }
    if (now < current.issued_at || now < current.limits.time_window.not_before) defects.push('invalid-mandate-binding');
    if (
      verifyEmbeddedMac(keyring, 'mandate-binding', current as unknown as Record<string, unknown>, 'binding') !== 'valid' ||
      authorizedAgentId === undefined ||
      current.authorized_agent.id !== authorizedAgentId
    ) {
      defects.push('invalid-mandate-binding');
    }
    if (current.ordering_rule !== 'latest-version-wins') defects.push('invalid-mandate-binding');
    if (current.connected_service !== input.service) defects.push('substituted-service');
    const exactAmount = input.proposal.exact_parameters['amount_minor_units'];
    const broadened =
      current.action_class !== input.actionClass ||
      !equalTarget(input.proposal.target, current.target) ||
      !input.proposal.data_to_be_disclosed.every((field) => current.permitted_data_fields.includes(field)) ||
      (input.proposal.data_to_be_disclosed.length > 0 && !current.disclosure_destinations.includes(input.service)) ||
      (input.proposal.cost_obligation.amount_minor_units > 0 &&
        exactAmount !== input.proposal.cost_obligation.amount_minor_units) ||
      (current.limits.amount_minor_units !== undefined &&
        input.proposal.cost_obligation.amount_minor_units > current.limits.amount_minor_units);
    if (broadened) defects.push('broadened-request');
  }

  const approved = current?.approved_models.find(
    (entry) =>
      entry.card_id === input.proposal.acting_model.card_id &&
      entry.card_version === input.proposal.acting_model.card_version &&
      entry.requested_id === input.proposal.acting_model.requested_id &&
      entry.roles.includes('acting'),
  );
  if (approved === undefined || !modelEvidence.servedModelAccepted) defects.push('substituted-model');
  if (modelEvidence.cardStatus === 'withdrawn' || (approved !== undefined && approved.card_digest !== modelEvidence.cardDigest)) {
    defects.push('stale-card');
  }

  if (
    state.policy === undefined ||
    state.policy.policy_version !== policy.policy.policy_version ||
    state.policy.policy_content_digest !== policy.policyContentDigest ||
    state.policy.evaluator_build_id !== policy.evaluatorBuildId
  ) {
    defects.push('stale-policy');
  }

  return {
    defects: unique(defects),
    mandate: current,
    cardDigest: approved?.card_digest ?? modelEvidence.cardDigest ?? ZERO_DIGEST,
    cardKeyId: modelEvidence.cardKeyId || 'unverified',
    reauthorizationRequired:
      modelEvidence.cardStatus === 'superseded' || approved?.re_confirmation_required === true,
  };
}

function requestedDeltas(input: RuleProposalInput): Partial<Record<CounterName, number>> {
  let notificationVolume = 0;
  if (input.actionClass === 'notification') {
    const declared = input.proposal.exact_parameters['notification_volume'];
    const recipients = input.proposal.exact_parameters['recipients'];
    if (declared === undefined) notificationVolume = Array.isArray(recipients) ? recipients.length : 1;
    else if (typeof declared === 'number' && Number.isSafeInteger(declared) && declared >= 0) {
      notificationVolume = declared;
    } else {
      throw new AuthorizationError(
        'invalid-counter-delta',
        'notification exact parameters must declare a non-negative integer notification_volume',
      );
    }
  }
  const deltas: Partial<Record<CounterName, number>> = {
    actions: 1,
    amount: input.proposal.cost_obligation.amount_minor_units,
    notification_volume: notificationVolume,
  };
  for (const [counter, delta] of Object.entries(deltas)) {
    if (!Number.isSafeInteger(delta)) {
      throw new AuthorizationError('invalid-counter-delta', `${counter} delta must be a safe integer`);
    }
  }
  return deltas;
}

function counterLimit(mandateValue: Mandate | undefined, counter: CounterName): number | null {
  if (mandateValue === undefined) return null;
  if (counter === 'actions') return mandateValue.limits.frequency_per_day ?? null;
  if (counter === 'amount') return mandateValue.limits.amount_minor_units ?? null;
  if (counter === 'notification_volume') return mandateValue.limits.notification_volume ?? null;
  return null;
}

function invalidationOps(state: WorldState, predicate: (ruling: GateRuling) => boolean, reason: string): WalOp[] {
  const ops: WalOp[] = [];
  for (const ruling of state.rulings.values()) {
    if (ruling.status !== 'issued' || !predicate(ruling)) continue;
    ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason });
    for (const reservation of ruling.counter_reservations) {
      if (state.reservations.get(reservation.id)?.state === 'reserved') {
        ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason });
      }
    }
  }
  return ops;
}

function authorityChainIds(mandateValue: Mandate | undefined): string[] {
  if (mandateValue === undefined) return [];
  return unique(mandateValue.authority_chain.flatMap((hop) => [hop.delegator, hop.delegate]));
}

function rulingRecord(
  input: RuleProposalInput,
  ruling: GateRuling,
  mandateValue: Mandate | undefined,
  entryId: string,
  at: string,
  intervention: { escalationId: string; contract: InterventionContract } | null,
): RecordEntry {
  return {
    world_id: input.proposal.world_id,
    entry_id: entryId,
    at,
    authenticated_actor: input.actor.credential,
    claimed_actor: { role: input.actor.claimed_role },
    proposed_action: input.proposal.proposed_action,
    basis: [
      ...input.proposal.material_inputs.map((item) => item.id),
      ...input.proposal.derived_claims.map((item) => item.id),
    ],
    authority_chain: authorityChainIds(mandateValue),
    admissibility_decision: { ruling_id: ruling.ruling_id, verdict: ruling.verdict },
    policy_model_version: {
      policy_version: ruling.policy_version,
      policy_content_digest: ruling.policy_content_digest,
      evaluator_build_id: ruling.evaluator_build_id,
      acting_model_requested_id: input.proposal.acting_model.requested_id,
      acting_model_served_id: input.proposal.acting_model.served_id,
    },
    commitment_and_effect: null,
    human_intervention_event:
      intervention === null
        ? null
        : {
            event: 'human_intervention_event',
            escalation_id: intervention.escalationId,
            payload: { kind: 'escalation_raised', contract: intervention.contract, reason: ruling.reason },
          },
    challenge_and_remedy: null,
  };
}

function expectedEffectIntent(state: WorldState, ruling: GateRuling): EffectIntent | undefined {
  const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
  if (proposal === undefined) return undefined;
  return effectIntent.parse({
    world_id: proposal.world_id,
    ruling_id: ruling.ruling_id,
    frozen_proposal_hash: proposal.proposal_hash,
    service: ruling.binding.service,
    action_class: ruling.binding.action_class,
    target: proposal.target,
    exact_parameters: proposal.exact_parameters,
    data_to_be_disclosed: proposal.data_to_be_disclosed,
  });
}

function commitmentRecordEntry(
  state: WorldState,
  ruling: GateRuling,
  actor: TransactionActor,
  entryId: string,
  commitmentId: string,
  effectId: string,
  idempotencyKey: string,
  effectRequestDigest: string,
  boundAt: string,
  tokenExpiresAt: string,
): RecordEntry {
  const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
  if (proposal === undefined) throw new Error(`ruling ${ruling.ruling_id} lost its proposal`);
  const mandateValue = state.mandates.get(mandateVersionKey(ruling.binding.mandate_id, ruling.binding.mandate_version));
  return {
    world_id: state.worldId,
    entry_id: entryId,
    at: boundAt,
    authenticated_actor: actor.credential,
    claimed_actor: { role: actor.claimed_role },
    proposed_action: proposal.proposed_action,
    basis: [...proposal.material_inputs.map((item) => item.id), ...proposal.derived_claims.map((item) => item.id)],
    authority_chain: authorityChainIds(mandateValue),
    admissibility_decision: { ruling_id: ruling.ruling_id, verdict: 'allow' },
    policy_model_version: {
      policy_version: ruling.policy_version,
      policy_content_digest: ruling.policy_content_digest,
      evaluator_build_id: ruling.evaluator_build_id,
      acting_model_requested_id: proposal.acting_model.requested_id,
      acting_model_served_id: proposal.acting_model.served_id,
    },
    commitment_and_effect: {
      event: 'commitment',
      commitment_id: commitmentId,
      ruling_id: ruling.ruling_id,
      effect_id: effectId,
      idempotency_key: idempotencyKey,
      frozen_proposal_hash: proposal.proposal_hash,
      effect_request_digest: effectRequestDigest,
      service: ruling.binding.service,
      bound_at: boundAt,
      token_expires_at: tokenExpiresAt,
    },
    human_intervention_event: null,
    challenge_and_remedy: null,
  };
}

export class AuthorizationCore {
  readonly #store: WalStore;
  readonly #keyring: Keyring;
  #policy: LoadedPolicy;
  readonly #rulingTtlMs: number;
  readonly #commitTokenTtlMs: number;
  readonly #ids: IdFactory;
  readonly #resolveAuthorizedAgent: (actor: TransactionActor) => string | undefined;
  readonly #resolveModelEvidence: (proposal: FrozenProposal) => ModelEvidence;

  constructor(options: AuthorizationCoreOptions) {
    this.#store = options.store;
    this.#keyring = options.keyring;
    this.#policy = options.policy;
    this.#rulingTtlMs = options.rulingTtlMs ?? 120_000;
    this.#commitTokenTtlMs = options.commitTokenTtlMs ?? 5_000;
    if (!Number.isSafeInteger(this.#rulingTtlMs) || this.#rulingTtlMs <= 0) {
      throw new RangeError('rulingTtlMs must be a positive safe integer');
    }
    if (!Number.isSafeInteger(this.#commitTokenTtlMs) || this.#commitTokenTtlMs <= 0) {
      throw new RangeError('commitTokenTtlMs must be a positive safe integer');
    }
    this.#ids = options.ids ?? defaultIds;
    this.#resolveAuthorizedAgent = options.resolveAuthorizedAgent;
    this.#resolveModelEvidence = options.resolveModelEvidence;
  }

  async activatePolicy(actor: TransactionActor = { credential: 'proc:authz', claimed_role: null }): Promise<void> {
    const policy = this.#policy;
    await this.#store.transactWithState('policy_reload', actor, (state, at) => ({
      ops:
        state.policy?.policy_version === policy.policy.policy_version &&
        state.policy.policy_content_digest === policy.policyContentDigest &&
        state.policy.evaluator_build_id === policy.evaluatorBuildId
          ? []
          : [
              ...invalidationOps(state, () => true, 'policy-reload'),
              {
                op: 'policy.reload' as const,
                policy: {
                  world_id: state.worldId,
                  policy_version: policy.policy.policy_version,
                  policy_content_digest: policy.policyContentDigest,
                  evaluator_build_id: policy.evaluatorBuildId,
                  activated_at: at,
                },
              },
            ],
      result: undefined,
    }));
  }

  async reloadPolicy(policy: LoadedPolicy, actor: TransactionActor): Promise<void> {
    await this.#store.transactWithState('policy_reload', actor, (state, at) => ({
      ops:
        state.policy?.policy_version === policy.policy.policy_version &&
        state.policy.policy_content_digest === policy.policyContentDigest &&
        state.policy.evaluator_build_id === policy.evaluatorBuildId
          ? []
          : [
              ...invalidationOps(state, () => true, 'policy-reload'),
              {
                op: 'policy.reload' as const,
                policy: {
                  world_id: state.worldId,
                  policy_version: policy.policy.policy_version,
                  policy_content_digest: policy.policyContentDigest,
                  evaluator_build_id: policy.evaluatorBuildId,
                  activated_at: at,
                },
              },
            ],
      result: undefined,
    }));
    this.#policy = policy;
  }

  async grantMandate(value: Mandate, actor: TransactionActor): Promise<void> {
    const parsed = mandate.parse(value);
    requireValidMandateMac(this.#keyring, parsed);
    await this.#store.transact('mandate_grant', actor, [{ op: 'mandate.grant', mandate: parsed }]);
  }

  async amendMandate(value: Mandate, actor: TransactionActor): Promise<void> {
    const parsed = mandate.parse(value);
    requireValidMandateMac(this.#keyring, parsed);
    await this.#store.transactWithState('mandate_amend', actor, (state) => ({
      ops: [
        ...invalidationOps(
          state,
          (ruling) => ruling.binding.mandate_id === parsed.mandate_id,
          'mandate-amendment',
        ),
        { op: 'mandate.amend', mandate: parsed },
      ],
      result: undefined,
    }));
  }

  async revokeMandate(mandateId: string, version: number, actor: TransactionActor): Promise<void> {
    await this.#store.transactWithState('mandate_revoke', actor, (state, at) => ({
      ops: [
        ...invalidationOps(
          state,
          (ruling) => ruling.binding.mandate_id === mandateId && ruling.binding.mandate_version === version,
          'mandate-revocation',
        ),
        { op: 'mandate.revoke', mandate_id: mandateId, version, revoked_at: at },
      ],
      result: undefined,
    }));
  }

  async ruleProposal(input: RuleProposalInput): Promise<RuleProposalResult> {
    const proposal = frozenProposal.parse(input.proposal);
    verifyProposalHash(proposal);
    const policy = this.#policy;
    const completed = await this.#store.transactWithState('ruling_issue', input.actor, (state, at) => {
      const existing = state.proposals.get(proposal.proposal_id);
      if (existing !== undefined && existing.proposal_hash !== proposal.proposal_hash) {
        throw new AuthorizationError('proposal-conflict', `proposal id ${proposal.proposal_id} is already frozen`);
      }
      const defects = authorityDefects(
        state,
        { ...input, proposal },
        policy,
        this.#keyring,
        at,
        this.#resolveAuthorizedAgent(input.actor),
        this.#resolveModelEvidence(proposal),
      );
      if (defects.defects.includes('stale-policy')) {
        throw new AuthorizationError('policy-not-active', 'the configured policy is not the active durable policy');
      }

      const deltas = requestedDeltas({ ...input, proposal });
      const counters = Object.fromEntries(
        (Object.entries(deltas) as [CounterName, number][]).map(([counter, delta]) => [
          counter,
          {
            current: counterValue(state, proposal.mandate_ref.mandate_id, counter, at),
            delta,
            limit: counterLimit(defects.mandate, counter),
          },
        ]),
      );
      const evaluation = evaluatePolicy(policy.policy, {
        gate: input.gate,
        proposal,
        mandate: defects.mandate,
        context: input.context ?? {},
        counters,
        signals: input.signals ?? [],
        screeningPerformed: input.screeningPerformed ?? false,
        patternEvents: state.patternEvents,
        now: at,
        authorityDefects: defects.defects,
        reauthorizationRequired: defects.reauthorizationRequired,
      });

      const rulingId = this.#ids.next('rul');
      const nonceId = this.#ids.next('nce');
      const mandateExpiry = defects.mandate?.expires_at;
      const mandateWindowEnd = defects.mandate?.limits.time_window.not_after;
      const ttlEnd = addMilliseconds(at, this.#rulingTtlMs);
      const notAfter =
        evaluation.verdict === 'deny'
          ? ttlEnd
          : [ttlEnd, mandateExpiry, mandateWindowEnd].filter((value): value is string => value !== undefined).sort()[0] ?? ttlEnd;
      const wouldExceed = Object.values(counters).some(
        (counter) => counter.limit !== null && counter.current + counter.delta > counter.limit,
      );
      const reserve = evaluation.verdict !== 'deny' && !wouldExceed;
      const reservations = reserve
        ? (Object.entries(deltas) as [CounterName, number][])
            .filter(([, delta]) => delta !== 0)
            .map(([counter, delta]) => ({ id: this.#ids.next('rsv'), counter, delta }))
        : [];
      const ruling = gateRuling.parse({
        world_id: proposal.world_id,
        ruling_id: rulingId,
        gate: input.gate,
        verdict: evaluation.verdict,
        matched_rule_id: evaluation.matchedRuleId,
        policy_version: policy.policy.policy_version,
        policy_content_digest: policy.policyContentDigest,
        evaluator_build_id: policy.evaluatorBuildId,
        binding: {
          frozen_proposal_hash: proposal.proposal_hash,
          mandate_id: proposal.mandate_ref.mandate_id,
          mandate_version: proposal.mandate_ref.version,
          acting_model_id: proposal.acting_model.requested_id,
          card_digest: defects.cardDigest,
          card_key_id: defects.cardKeyId,
          service: input.service,
          action_class: input.actionClass,
          nonce: nonceId,
          validity_window: { not_before: at, not_after: notAfter },
        },
        ux_class: evaluation.uxClass,
        reason: evaluation.reason,
        evidence_refs: input.signals ?? [],
        counter_reservations: reservations,
        issued_at: at,
        status: 'issued',
        successor_ruling_id: null,
      });
      const escalationId = evaluation.verdict === 'escalate' ? this.#ids.next('esc') : null;
      const recordEntryId = this.#ids.next('rec');
      const ops: WalOp[] = [];
      if (existing === undefined) ops.push({ op: 'proposal.freeze', proposal });
      ops.push({
        op: 'nonce.issue',
        nonce: {
          world_id: proposal.world_id,
          nonce_id: nonceId,
          ruling_id: rulingId,
          expires_at: notAfter,
          state: 'issued',
        },
      });
      for (const reservation of reservations) {
        ops.push({
          op: 'reservation.reserve',
          reservation: {
            world_id: proposal.world_id,
            reservation_id: reservation.id,
            ruling_id: rulingId,
            mandate_id: proposal.mandate_ref.mandate_id,
            mandate_version: proposal.mandate_ref.version,
            counter: reservation.counter,
            delta: reservation.delta,
            reserved_at: at,
            expires_at: notAfter,
            state_changed_at: at,
            state: 'reserved',
          },
        });
      }
      ops.push({ op: 'ruling.issue', ruling });

      let mandateNarrowed = false;
      let contract: InterventionContract | null = null;
      if (escalationId !== null) {
        contract = evaluation.interventionContract;
        if (contract === null) throw new Error('an escalate verdict must carry an intervention contract');
        const escalationExpires = addMilliseconds(at, contract.response_bound_and_default.response_bound_ms);
        ops.push({
          op: 'escalation.open',
          escalation: {
            world_id: proposal.world_id,
            escalation_id: escalationId,
            ruling_id: rulingId,
            frozen_proposal_hash: proposal.proposal_hash,
            contract,
            opened_at: at,
            expires_at: escalationExpires,
            state: 'open',
            terminal_disposition: null,
            successor_ruling_id: null,
          },
        });
        const pattern: PatternEvent = {
          world_id: proposal.world_id,
          event_id: this.#ids.next('pat'),
          mandate_id: proposal.mandate_ref.mandate_id,
          escalation_id: escalationId,
          kind: 'escalation',
          at,
        };
        ops.push({ op: 'pattern.record', event: pattern });
        if (
          defects.mandate?.state === 'active' &&
          escalationPatternRequiresNarrowing(
            policy.policy,
            [...state.patternEvents, pattern],
            defects.mandate.mandate_id,
            at,
          )
        ) {
          mandateNarrowed = true;
          ops.push(
            ...invalidationOps(
              state,
              (candidate) => candidate.binding.mandate_id === defects.mandate?.mandate_id,
              'escalation-pattern-narrowing',
            ),
          );
          ops.push({ op: 'ruling.invalidate', ruling_id: rulingId, reason: 'escalation-pattern-narrowing' });
          for (const reservation of reservations) {
            ops.push({
              op: 'reservation.release',
              reservation_id: reservation.id,
              reason: 'escalation-pattern-narrowing',
            });
          }
          ops.push({
            op: 'mandate.amend',
            mandate: bindMandate(this.#keyring, {
              ...mandateBody(defects.mandate),
              version: defects.mandate.version + 1,
              state: 'suspended',
              issued_at: at,
            }),
          });
        }
      }

      const entry = rulingRecord(
        { ...input, proposal },
        ruling,
        defects.mandate,
        recordEntryId,
        at,
        escalationId === null || contract === null ? null : { escalationId, contract },
      );
      ops.push({ op: 'record.action.append', entry });
      return { ops, result: { ruling, escalationId, recordEntryId, mandateNarrowed } };
    });
    return completed.result;
  }

  async commitVerify(input: CommitVerifyInput): Promise<CommitVerifyResult> {
    const intent = effectIntent.parse(input.intent);
    const completed = await this.#store.transactWithState<CommitVerifyResult>('commit_verify', input.actor, (state, at) => {
      const ruling = state.rulings.get(input.rulingId);
      if (ruling === undefined) return { ops: [], result: { ok: false, defect: 'replayed-ruling' } as const };
      if (ruling.status !== 'issued') {
        return { ops: [], result: { ok: false, defect: 'replayed-ruling' } as const };
      }
      if (ruling.verdict !== 'allow') return { ops: [], result: { ok: false, defect: 'not-allowed' } as const };

      const expiryOps: WalOp[] = [];
      if (at >= ruling.binding.validity_window.not_after) {
        expiryOps.push({ op: 'ruling.expire', ruling_id: ruling.ruling_id });
        const nonce = state.nonces.get(ruling.binding.nonce);
        if (nonce?.state === 'issued') expiryOps.push({ op: 'nonce.expire', nonce_id: nonce.nonce_id });
        for (const reservation of ruling.counter_reservations) {
          if (state.reservations.get(reservation.id)?.state === 'reserved') {
            expiryOps.push({ op: 'reservation.release', reservation_id: reservation.id, reason: 'ruling-expiry' });
          }
        }
        return { ops: expiryOps, result: { ok: false, defect: 'expired-ruling' } as const };
      }

      const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
      const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
      const expectedIntent = expectedEffectIntent(state, ruling);
      if (
        proposal === undefined ||
        expectedIntent === undefined ||
        canonicalize(intent) !== canonicalize(expectedIntent)
      ) {
        return { ops: [], result: { ok: false, defect: 'proposal-mismatch' } as const };
      }

      const mandateStatus = state.mandateStatus.get(ruling.binding.mandate_id);
      const mandateValue = state.mandates.get(
        mandateVersionKey(ruling.binding.mandate_id, ruling.binding.mandate_version),
      );
      let defect: CommitDefect | undefined;
      if (mandateStatus === undefined || mandateValue === undefined) defect = 'missing-mandate';
      else if (mandateStatus.version !== ruling.binding.mandate_version) defect = 'invalid-mandate-binding';
      else if (mandateStatus.state === 'revoked') defect = 'revoked-mandate';
      else if (mandateStatus.state === 'suspended') defect = 'suspended-mandate';
      else if (
        mandateStatus.state === 'expired' ||
        at > mandateValue.expires_at ||
        at > mandateValue.limits.time_window.not_after
      ) {
        defect = 'expired-mandate';
      } else if (
        verifyEmbeddedMac(
          this.#keyring,
          'mandate-binding',
          mandateValue as unknown as Record<string, unknown>,
          'binding',
        ) !== 'valid'
      ) {
        defect = 'invalid-mandate-binding';
      } else if (
        mandateValue.connected_service !== ruling.binding.service ||
        mandateValue.action_class !== ruling.binding.action_class
      ) {
        defect = 'substituted-service';
      } else {
        const approved = mandateValue.approved_models.find(
          (entry) =>
            entry.requested_id === proposal.acting_model.requested_id &&
            entry.card_id === proposal.acting_model.card_id &&
            entry.card_version === proposal.acting_model.card_version &&
            entry.roles.includes('acting'),
        );
        if (approved === undefined || approved.card_digest !== ruling.binding.card_digest) defect = 'substituted-model';
        else if (approved.re_confirmation_required === true) defect = 'stale-card';
      }
      if (
        defect === undefined &&
        (state.policy === undefined ||
          state.policy.policy_version !== ruling.policy_version ||
          state.policy.policy_content_digest !== ruling.policy_content_digest ||
          state.policy.evaluator_build_id !== ruling.evaluator_build_id)
      ) {
        defect = 'stale-policy';
      }
      const nonce = state.nonces.get(ruling.binding.nonce);
      if (defect === undefined && (nonce === undefined || nonce.state !== 'issued')) defect = 'replayed-ruling';
      if (defect === undefined) {
        for (const reservation of ruling.counter_reservations) {
          const stored = state.reservations.get(reservation.id);
          if (stored === undefined || stored.state !== 'reserved') {
            defect = 'counter-invalid';
            break;
          }
          const limit = counterLimit(mandateValue, reservation.counter);
          if (
            limit !== null &&
            counterValue(state, ruling.binding.mandate_id, reservation.counter, at) > limit
          ) {
            defect = 'counter-invalid';
            break;
          }
        }
      }
      if (defect !== undefined) {
        const ops: WalOp[] = [
          { op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason: `commit-verify:${defect}` },
        ];
        for (const reservation of ruling.counter_reservations) {
          if (state.reservations.get(reservation.id)?.state === 'reserved') {
            ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason: `commit-verify:${defect}` });
          }
        }
        return { ops, result: { ok: false, defect } as const };
      }

      const effectRequestDigest = digestFor('proposal', intent);
      const idempotencyKey = sha256Hex(
        canonicalize({ world_id: state.worldId, ruling_id: ruling.ruling_id, nonce: ruling.binding.nonce }),
      );
      const commitmentId = this.#ids.next('cmt');
      const effectId = this.#ids.next('eff');
      const recordEntryId = this.#ids.next('rec');
      const tokenExpiresAt = addMilliseconds(at, this.#commitTokenTtlMs);
      const unsignedToken = {
        world_id: state.worldId,
        effect_id: effectId,
        ruling_id: ruling.ruling_id,
        frozen_proposal_hash: ruling.binding.frozen_proposal_hash,
        effect_request_digest: effectRequestDigest,
        idempotency_key: idempotencyKey,
        service: ruling.binding.service,
        action_class: ruling.binding.action_class,
        expires_at: tokenExpiresAt,
      };
      const token = commitToken.parse(createEmbeddedMac(this.#keyring, 'commit-token', unsignedToken, 'mac'));
      const ops: WalOp[] = [{ op: 'nonce.consume', nonce_id: ruling.binding.nonce }];
      for (const reservation of ruling.counter_reservations) {
        ops.push({ op: 'reservation.settle', reservation_id: reservation.id });
      }
      ops.push(
        { op: 'ruling.consume', ruling_id: ruling.ruling_id },
        {
          op: 'commitment.bind',
          commitment: {
            world_id: state.worldId,
            commitment_id: commitmentId,
            ruling_id: ruling.ruling_id,
            frozen_proposal_hash: ruling.binding.frozen_proposal_hash,
            effect_id: effectId,
            effect_request_digest: effectRequestDigest,
            idempotency_key: idempotencyKey,
            service: ruling.binding.service,
            action_class: ruling.binding.action_class,
            bound_at: at,
            token_expires_at: tokenExpiresAt,
            services_host_boot_id: input.servicesHostBootId,
            state: 'bound',
            outcome: null,
            recovery_owner_role: input.recoveryOwnerRole ?? 'principal',
          },
        },
        {
          op: 'record.action.append',
          entry: commitmentRecordEntry(
            state,
            ruling,
            input.actor,
            recordEntryId,
            commitmentId,
            effectId,
            idempotencyKey,
            effectRequestDigest,
            at,
            tokenExpiresAt,
          ),
        },
      );
      return { ops, result: { ok: true, token, commitmentId, recordEntryId } as const };
    });
    return completed.result;
  }
}
