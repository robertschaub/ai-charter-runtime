// SPDX-License-Identifier: AGPL-3.0-only
/** Deterministic replay state and the sole mutation path for WAL operations. */
import type { z } from 'zod';

import { digestFor, verifyDigest } from './hash.js';
import type {
  CommitmentRecord,
  EffectRecord,
  EscalationRecord,
  FrozenProposal,
  GateRuling,
  Mandate,
  ModelSelectionRecord,
  NonceRecord,
  PatternEvent,
  PolicyActivation,
  RecordEntry,
  ReservationRecord,
  ReviewObligation,
  StoreItem,
  WalOp,
} from './schemas/index.js';
import type { accessChainEntry } from './schemas/record.js';

type AccessChainValue = z.infer<typeof accessChainEntry>;

export class StateTransitionError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'StateTransitionError';
  }
}

export interface MandateRuntimeStatus {
  readonly version: number;
  readonly state: 'active' | 'suspended' | 'expired' | 'revoked';
  readonly changed_at: string;
}

export interface WorldState {
  readonly worldId: string;
  lastTimestamp: string | undefined;
  readonly mandates: Map<string, Mandate>;
  readonly mandateStatus: Map<string, MandateRuntimeStatus>;
  readonly proposals: Map<string, FrozenProposal>;
  readonly proposalByHash: Map<string, string>;
  readonly nonces: Map<string, NonceRecord>;
  readonly reservations: Map<string, ReservationRecord>;
  readonly rulings: Map<string, GateRuling>;
  readonly commitments: Map<string, CommitmentRecord>;
  readonly effects: Map<string, EffectRecord>;
  readonly effectByIdempotencyKey: Map<string, string>;
  readonly escalations: Map<string, EscalationRecord>;
  readonly storeItems: Map<string, StoreItem>;
  readonly patternEvents: PatternEvent[];
  readonly modelSelections: ModelSelectionRecord[];
  readonly reviews: Map<string, ReviewObligation>;
  readonly actionRecords: RecordEntry[];
  readonly accessRecords: AccessChainValue[];
  policy: PolicyActivation | undefined;
}

export function mandateVersionKey(mandateId: string, version: number): string {
  return `${mandateId}@${version}`;
}

export function createWorldState(worldId: string): WorldState {
  return {
    worldId,
    lastTimestamp: undefined,
    mandates: new Map(),
    mandateStatus: new Map(),
    proposals: new Map(),
    proposalByHash: new Map(),
    nonces: new Map(),
    reservations: new Map(),
    rulings: new Map(),
    commitments: new Map(),
    effects: new Map(),
    effectByIdempotencyKey: new Map(),
    escalations: new Map(),
    storeItems: new Map(),
    patternEvents: [],
    modelSelections: [],
    reviews: new Map(),
    actionRecords: [],
    accessRecords: [],
    policy: undefined,
  };
}

export function cloneWorldState(state: WorldState): WorldState {
  return {
    worldId: state.worldId,
    lastTimestamp: state.lastTimestamp,
    mandates: new Map(state.mandates),
    mandateStatus: new Map(state.mandateStatus),
    proposals: new Map(state.proposals),
    proposalByHash: new Map(state.proposalByHash),
    nonces: new Map(state.nonces),
    reservations: new Map(state.reservations),
    rulings: new Map(state.rulings),
    commitments: new Map(state.commitments),
    effects: new Map(state.effects),
    effectByIdempotencyKey: new Map(state.effectByIdempotencyKey),
    escalations: new Map(state.escalations),
    storeItems: new Map(state.storeItems),
    patternEvents: [...state.patternEvents],
    modelSelections: [...state.modelSelections],
    reviews: new Map(state.reviews),
    actionRecords: [...state.actionRecords],
    accessRecords: [...state.accessRecords],
    policy: state.policy,
  };
}

function fail(code: string, message: string): never {
  throw new StateTransitionError(code, message);
}

function requireWorld(state: WorldState, value: { world_id: string }, label: string): void {
  if (value.world_id !== state.worldId) fail('world-mismatch', `${label} belongs to ${value.world_id}, not ${state.worldId}`);
}

function requireValue<K, V>(map: ReadonlyMap<K, V>, key: K, label: string): V {
  const value = map.get(key);
  if (value === undefined) fail('missing-state', `${label} does not exist`);
  return value;
}

function requireUnique<K>(map: ReadonlyMap<K, unknown>, key: K, label: string): void {
  if (map.has(key)) fail('duplicate-state', `${label} already exists`);
}

function proposalDigest(proposal: FrozenProposal): string {
  const { proposal_hash: ignored, ...body } = proposal;
  void ignored;
  return digestFor('proposal', body);
}

function transitionNonce(state: WorldState, nonceId: string, target: 'consumed' | 'expired'): void {
  const current = requireValue(state.nonces, nonceId, `nonce ${nonceId}`);
  if (current.state !== 'issued') fail('illegal-transition', `nonce ${nonceId}: ${current.state} -> ${target}`);
  state.nonces.set(nonceId, { ...current, state: target });
}

function transitionReservation(
  state: WorldState,
  reservationId: string,
  target: ReservationRecord['state'],
  transactionTimestamp: string,
): void {
  const current = requireValue(state.reservations, reservationId, `reservation ${reservationId}`);
  const allowed: Record<ReservationRecord['state'], readonly ReservationRecord['state'][]> = {
    reserved: ['settled', 'released'],
    settled: ['held_for_reconciliation'],
    held_for_reconciliation: ['settled', 'released'],
    released: [],
  };
  if (!allowed[current.state].includes(target)) {
    fail('illegal-transition', `reservation ${reservationId}: ${current.state} -> ${target}`);
  }
  state.reservations.set(reservationId, { ...current, state: target, state_changed_at: transactionTimestamp });
}

function transitionRuling(state: WorldState, rulingId: string, target: 'consumed' | 'invalidated' | 'expired'): void {
  const current = requireValue(state.rulings, rulingId, `ruling ${rulingId}`);
  if (current.status !== 'issued') fail('illegal-transition', `ruling ${rulingId}: ${current.status} -> ${target}`);
  state.rulings.set(rulingId, { ...current, status: target });
}

function recordAccessId(entry: AccessChainValue): string {
  if ('entry_id' in entry) return entry.entry_id;
  return `${entry.event}:${entry.checkpoint_id}`;
}

export function applyWorldOp(state: WorldState, op: WalOp, transactionTimestamp: string): void {
  switch (op.op) {
    case 'proposal.freeze': {
      requireWorld(state, op.proposal, 'proposal');
      requireUnique(state.proposals, op.proposal.proposal_id, `proposal ${op.proposal.proposal_id}`);
      if (!verifyDigest(op.proposal.proposal_hash, proposalDigest(op.proposal))) {
        fail('proposal-hash', `proposal ${op.proposal.proposal_id} has the wrong frozen hash`);
      }
      if (state.proposalByHash.has(op.proposal.proposal_hash)) {
        fail('duplicate-state', `proposal hash ${op.proposal.proposal_hash} already exists`);
      }
      const actionRevisions = [...state.proposals.values()]
        .filter((proposal) => proposal.action_id === op.proposal.action_id)
        .map((proposal) => proposal.revision);
      const expectedRevision = actionRevisions.length === 0 ? 1 : Math.max(...actionRevisions) + 1;
      if (op.proposal.revision !== expectedRevision) {
        fail(
          'proposal-revision',
          `proposal ${op.proposal.proposal_id} must be revision ${expectedRevision} for action ${op.proposal.action_id}`,
        );
      }
      state.proposals.set(op.proposal.proposal_id, op.proposal);
      state.proposalByHash.set(op.proposal.proposal_hash, op.proposal.proposal_id);
      break;
    }
    case 'nonce.issue': {
      requireWorld(state, op.nonce, 'nonce');
      if (op.nonce.state !== 'issued') fail('illegal-initial-state', 'a new nonce must be issued');
      requireUnique(state.nonces, op.nonce.nonce_id, `nonce ${op.nonce.nonce_id}`);
      state.nonces.set(op.nonce.nonce_id, op.nonce);
      break;
    }
    case 'nonce.consume':
      transitionNonce(state, op.nonce_id, 'consumed');
      break;
    case 'nonce.expire':
      transitionNonce(state, op.nonce_id, 'expired');
      break;
    case 'reservation.reserve': {
      requireWorld(state, op.reservation, 'reservation');
      if (op.reservation.state !== 'reserved') fail('illegal-initial-state', 'a new reservation must be reserved');
      requireUnique(state.reservations, op.reservation.reservation_id, `reservation ${op.reservation.reservation_id}`);
      requireValue(
        state.mandates,
        mandateVersionKey(op.reservation.mandate_id, op.reservation.mandate_version),
        `mandate ${op.reservation.mandate_id}@${op.reservation.mandate_version}`,
      );
      state.reservations.set(op.reservation.reservation_id, op.reservation);
      break;
    }
    case 'reservation.settle':
      {
        const reservation = requireValue(state.reservations, op.reservation_id, `reservation ${op.reservation_id}`);
        const ruling = requireValue(state.rulings, reservation.ruling_id, `ruling ${reservation.ruling_id}`);
        const nonce = requireValue(state.nonces, ruling.binding.nonce, `nonce ${ruling.binding.nonce}`);
        if (ruling.verdict !== 'allow' || nonce.state !== 'consumed') {
          fail('illegal-transition', `reservation ${op.reservation_id} can settle only for a consumed allow nonce`);
        }
      }
      transitionReservation(state, op.reservation_id, 'settled', transactionTimestamp);
      break;
    case 'reservation.release':
      transitionReservation(state, op.reservation_id, 'released', transactionTimestamp);
      break;
    case 'reservation.hold_for_reconciliation':
      transitionReservation(state, op.reservation_id, 'held_for_reconciliation', transactionTimestamp);
      break;
    case 'reservation.reconcile':
      transitionReservation(state, op.reservation_id, op.resolution, transactionTimestamp);
      break;
    case 'ruling.issue': {
      requireWorld(state, op.ruling, 'ruling');
      if (op.ruling.status !== 'issued') fail('illegal-initial-state', 'a new ruling must be issued');
      requireUnique(state.rulings, op.ruling.ruling_id, `ruling ${op.ruling.ruling_id}`);
      const proposalId = state.proposalByHash.get(op.ruling.binding.frozen_proposal_hash);
      if (proposalId === undefined) {
        fail('missing-state', `ruling ${op.ruling.ruling_id} refers to an unknown proposal hash`);
      }
      const proposal = requireValue(state.proposals, proposalId, `proposal ${proposalId}`);
      if (proposal.acting_model.requested_id !== op.ruling.binding.acting_model_id) {
        fail('binding-mismatch', `ruling ${op.ruling.ruling_id} differs from its proposal model`);
      }
      if (op.ruling.verdict !== 'deny') {
        const mandate = requireValue(
          state.mandates,
          mandateVersionKey(op.ruling.binding.mandate_id, op.ruling.binding.mandate_version),
          `mandate ${op.ruling.binding.mandate_id}@${op.ruling.binding.mandate_version}`,
        );
        if (
          proposal.mandate_ref.mandate_id !== mandate.mandate_id ||
          proposal.mandate_ref.version !== mandate.version ||
          mandate.connected_service !== op.ruling.binding.service ||
          mandate.action_class !== op.ruling.binding.action_class
        ) {
          fail('binding-mismatch', `ruling ${op.ruling.ruling_id} differs from its proposal or mandate`);
        }
        const approvedModel = mandate.approved_models.find(
          (entry) =>
            entry.card_id === proposal.acting_model.card_id &&
            entry.card_version === proposal.acting_model.card_version &&
            entry.requested_id === proposal.acting_model.requested_id &&
            entry.roles.includes('acting'),
        );
        if (approvedModel === undefined || approvedModel.card_digest !== op.ruling.binding.card_digest) {
          fail('binding-mismatch', `ruling ${op.ruling.ruling_id} is not bound to an approved acting-model entry`);
        }
        if (
          op.ruling.binding.validity_window.not_before < mandate.limits.time_window.not_before ||
          op.ruling.binding.validity_window.not_after > mandate.limits.time_window.not_after ||
          op.ruling.binding.validity_window.not_after > mandate.expires_at
        ) {
          fail('binding-mismatch', `ruling ${op.ruling.ruling_id} outlives its mandate`);
        }
      }
      const nonce = requireValue(state.nonces, op.ruling.binding.nonce, `nonce ${op.ruling.binding.nonce}`);
      if (
        nonce.ruling_id !== op.ruling.ruling_id ||
        nonce.state !== 'issued' ||
        nonce.expires_at !== op.ruling.binding.validity_window.not_after
      ) {
        fail('binding-mismatch', `ruling ${op.ruling.ruling_id} does not own its issued nonce`);
      }
      for (const reservation of op.ruling.counter_reservations) {
        const stored = requireValue(state.reservations, reservation.id, `reservation ${reservation.id}`);
        if (
          stored.ruling_id !== op.ruling.ruling_id ||
          stored.counter !== reservation.counter ||
          stored.delta !== reservation.delta ||
          stored.state !== 'reserved'
        ) {
          fail('binding-mismatch', `ruling ${op.ruling.ruling_id} does not own reservation ${reservation.id}`);
        }
      }
      state.rulings.set(op.ruling.ruling_id, op.ruling);
      break;
    }
    case 'ruling.consume': {
      const current = requireValue(state.rulings, op.ruling_id, `ruling ${op.ruling_id}`);
      const nonce = requireValue(state.nonces, current.binding.nonce, `nonce ${current.binding.nonce}`);
      if (current.verdict !== 'allow' || nonce.state !== 'consumed') {
        fail('illegal-transition', `only an allow ruling with a consumed nonce can be consumed`);
      }
      transitionRuling(state, op.ruling_id, 'consumed');
      break;
    }
    case 'ruling.invalidate':
      transitionRuling(state, op.ruling_id, 'invalidated');
      break;
    case 'ruling.expire':
      transitionRuling(state, op.ruling_id, 'expired');
      break;
    case 'ruling.link_successor': {
      const current = requireValue(state.rulings, op.ruling_id, `ruling ${op.ruling_id}`);
      requireValue(state.rulings, op.successor_ruling_id, `successor ruling ${op.successor_ruling_id}`);
      if (current.successor_ruling_id) fail('illegal-transition', `ruling ${op.ruling_id} already has a successor`);
      state.rulings.set(op.ruling_id, { ...current, successor_ruling_id: op.successor_ruling_id });
      break;
    }
    case 'commitment.bind': {
      requireWorld(state, op.commitment, 'commitment');
      if (op.commitment.state !== 'bound') fail('illegal-initial-state', 'a new commitment must be bound');
      if (op.commitment.recovery_owner_role !== op.commitment.recovery_contract.decision_and_route.eligible_role) {
        fail('binding-mismatch', 'commitment recovery owner differs from its pinned recovery contract');
      }
      requireUnique(state.commitments, op.commitment.commitment_id, `commitment ${op.commitment.commitment_id}`);
      const ruling = requireValue(state.rulings, op.commitment.ruling_id, `ruling ${op.commitment.ruling_id}`);
      if (ruling.status !== 'consumed' || ruling.verdict !== 'allow') {
        fail('illegal-transition', 'a commitment requires a consumed allow ruling');
      }
      if (ruling.binding.frozen_proposal_hash !== op.commitment.frozen_proposal_hash) {
        fail('binding-mismatch', 'commitment proposal hash differs from its ruling');
      }
      for (const reservation of ruling.counter_reservations) {
        if (state.reservations.get(reservation.id)?.state !== 'settled') {
          fail('illegal-transition', `commitment ${op.commitment.commitment_id} has an unsettled reservation`);
        }
      }
      if (
        state.effectByIdempotencyKey.has(op.commitment.idempotency_key) ||
        [...state.commitments.values()].some(
          (commitment) => commitment.idempotency_key === op.commitment.idempotency_key,
        )
      ) {
        fail('duplicate-state', `idempotency key ${op.commitment.idempotency_key} is already recorded`);
      }
      state.commitments.set(op.commitment.commitment_id, op.commitment);
      break;
    }
    case 'commitment.discharge': {
      const current = requireValue(state.commitments, op.commitment_id, `commitment ${op.commitment_id}`);
      if (current.state !== 'bound' && current.state !== 'unknown') {
        fail('illegal-transition', `commitment ${op.commitment_id}: ${current.state} -> discharged`);
      }
      const effect = state.effects.get(current.effect_id);
      if (effect === undefined || effect.outcome !== op.outcome) {
        fail('binding-mismatch', `commitment ${op.commitment_id} has no matching durable effect outcome`);
      }
      state.commitments.set(op.commitment_id, { ...current, state: 'discharged', outcome: op.outcome });
      break;
    }
    case 'commitment.mark_unknown': {
      const current = requireValue(state.commitments, op.commitment_id, `commitment ${op.commitment_id}`);
      if (current.state !== 'bound') fail('illegal-transition', `commitment ${op.commitment_id}: ${current.state} -> unknown`);
      if (state.effects.has(current.effect_id)) {
        fail('illegal-transition', `commitment ${op.commitment_id} already has a durable effect outcome`);
      }
      state.commitments.set(op.commitment_id, {
        ...current,
        state: 'unknown',
        outcome: 'unknown-reconciliation-required',
        recovery_owner_role: op.recovery_owner_role,
      });
      break;
    }
    case 'commitment.reconcile': {
      const current = requireValue(state.commitments, op.commitment_id, `commitment ${op.commitment_id}`);
      if (current.state !== 'unknown') fail('illegal-transition', `commitment ${op.commitment_id}: ${current.state} -> reconciled`);
      state.commitments.set(op.commitment_id, {
        ...current,
        state: 'reconciled',
        outcome: op.resolution === 'routed' ? 'unknown-reconciliation-required' : op.resolution,
      });
      break;
    }
    case 'escalation.open': {
      requireWorld(state, op.escalation, 'escalation');
      if (op.escalation.state !== 'open') fail('illegal-initial-state', 'a new escalation must be open');
      requireUnique(state.escalations, op.escalation.escalation_id, `escalation ${op.escalation.escalation_id}`);
      const ruling = requireValue(state.rulings, op.escalation.ruling_id, `ruling ${op.escalation.ruling_id}`);
      if (op.escalation.source_commitment_id === null) {
        if (ruling.verdict !== 'escalate') fail('binding-mismatch', 'only an escalate ruling can open a ruling escalation');
      } else {
        const commitment = requireValue(
          state.commitments,
          op.escalation.source_commitment_id,
          `commitment ${op.escalation.source_commitment_id}`,
        );
        if (
          commitment.state !== 'unknown' ||
          commitment.ruling_id !== ruling.ruling_id ||
          commitment.frozen_proposal_hash !== op.escalation.frozen_proposal_hash ||
          op.escalation.contract.trigger_and_state.trigger !== 'effect-outcome-unknown'
        ) {
          fail('binding-mismatch', 'a recovery escalation requires its matching unknown commitment');
        }
      }
      state.escalations.set(op.escalation.escalation_id, op.escalation);
      break;
    }
    case 'escalation.dispose': {
      const current = requireValue(state.escalations, op.escalation_id, `escalation ${op.escalation_id}`);
      if (current.state !== 'open') fail('illegal-transition', `escalation ${op.escalation_id} is already ${current.state}`);
      if (!current.contract.permitted_dispositions.includes(op.disposition)) {
        fail('disposition-not-permitted', `disposition ${op.disposition} is not permitted`);
      }
      state.escalations.set(op.escalation_id, {
        ...current,
        state: 'disposed',
        terminal_disposition: op.disposition,
      });
      break;
    }
    case 'escalation.timeout': {
      const current = requireValue(state.escalations, op.escalation_id, `escalation ${op.escalation_id}`);
      if (current.state !== 'open') fail('illegal-transition', `escalation ${op.escalation_id} is already ${current.state}`);
      const expected = current.contract.response_bound_and_default.safe_default.disposition;
      if (op.applied_default !== expected) fail('unsafe-default', `timeout must apply ${expected}, not ${op.applied_default}`);
      state.escalations.set(op.escalation_id, {
        ...current,
        state: 'timed_out',
        terminal_disposition: op.applied_default,
      });
      break;
    }
    case 'escalation.cancel': {
      const current = requireValue(state.escalations, op.escalation_id, `escalation ${op.escalation_id}`);
      if (current.state !== 'open') fail('illegal-transition', `escalation ${op.escalation_id} is already ${current.state}`);
      state.escalations.set(op.escalation_id, { ...current, state: 'cancelled' });
      break;
    }
    case 'effect.record': {
      requireWorld(state, op.effect, 'effect');
      requireUnique(state.effects, op.effect.effect_id, `effect ${op.effect.effect_id}`);
      const commitment = requireValue(
        state.commitments,
        op.effect.commitment_id,
        `commitment ${op.effect.commitment_id}`,
      );
      if (
        commitment.effect_id !== op.effect.effect_id ||
        commitment.idempotency_key !== op.effect.idempotency_key ||
        commitment.effect_request_digest !== op.effect.effect_request_digest
      ) {
        fail('binding-mismatch', `effect ${op.effect.effect_id} differs from its commitment`);
      }
      if (commitment.state !== 'bound' && commitment.state !== 'unknown') {
        fail('illegal-transition', `effect ${op.effect.effect_id} cannot attach to ${commitment.state} commitment`);
      }
      if (op.effect.outcome === 'unknown-reconciliation-required') {
        fail('illegal-transition', 'the services host cannot durably record an unknown effect outcome');
      }
      const existing = state.effectByIdempotencyKey.get(op.effect.idempotency_key);
      if (existing !== undefined) fail('duplicate-state', `idempotency key already belongs to ${existing}`);
      state.effects.set(op.effect.effect_id, op.effect);
      state.effectByIdempotencyKey.set(op.effect.idempotency_key, op.effect.effect_id);
      break;
    }
    case 'mandate.grant': {
      requireWorld(state, op.mandate, 'mandate');
      if (op.mandate.version !== 1) fail('mandate-version', 'a granted mandate starts at version 1');
      if (state.mandateStatus.has(op.mandate.mandate_id)) fail('duplicate-state', `mandate ${op.mandate.mandate_id} exists`);
      state.mandates.set(mandateVersionKey(op.mandate.mandate_id, op.mandate.version), op.mandate);
      state.mandateStatus.set(op.mandate.mandate_id, {
        version: op.mandate.version,
        state: op.mandate.state,
        changed_at: transactionTimestamp,
      });
      break;
    }
    case 'mandate.amend': {
      requireWorld(state, op.mandate, 'mandate');
      const current = requireValue(state.mandateStatus, op.mandate.mandate_id, `mandate ${op.mandate.mandate_id}`);
      if (current.state === 'revoked') fail('illegal-transition', 'a revoked mandate cannot be amended');
      if (op.mandate.version !== current.version + 1) {
        fail('mandate-version', `mandate amendment must be version ${current.version + 1}`);
      }
      state.mandates.set(mandateVersionKey(op.mandate.mandate_id, op.mandate.version), op.mandate);
      state.mandateStatus.set(op.mandate.mandate_id, {
        version: op.mandate.version,
        state: op.mandate.state,
        changed_at: transactionTimestamp,
      });
      break;
    }
    case 'mandate.revoke': {
      const current = requireValue(state.mandateStatus, op.mandate_id, `mandate ${op.mandate_id}`);
      if (current.state === 'revoked' || current.version !== op.version) {
        fail('illegal-transition', `cannot revoke mandate ${op.mandate_id}@${op.version}`);
      }
      state.mandateStatus.set(op.mandate_id, { version: current.version, state: 'revoked', changed_at: op.revoked_at });
      break;
    }
    case 'mandate.expire': {
      const current = requireValue(state.mandateStatus, op.mandate_id, `mandate ${op.mandate_id}`);
      if (current.version !== op.version || current.state === 'revoked' || current.state === 'expired') {
        fail('illegal-transition', `cannot expire mandate ${op.mandate_id}@${op.version}`);
      }
      state.mandateStatus.set(op.mandate_id, {
        version: current.version,
        state: 'expired',
        changed_at: op.expired_at,
      });
      break;
    }
    case 'policy.reload':
      requireWorld(state, op.policy, 'policy activation');
      state.policy = op.policy;
      break;
    case 'store.put':
      requireUnique(state.storeItems, op.item.id, `store item ${op.item.id}`);
      state.storeItems.set(op.item.id, op.item);
      break;
    case 'store.remove':
      requireValue(state.storeItems, op.item_id, `store item ${op.item_id}`);
      state.storeItems.delete(op.item_id);
      break;
    case 'pattern.record':
      requireWorld(state, op.event, 'pattern event');
      if (state.patternEvents.some((event) => event.event_id === op.event.event_id)) {
        fail('duplicate-state', `pattern event ${op.event.event_id} exists`);
      }
      state.patternEvents.push(op.event);
      break;
    case 'model.select':
      requireWorld(state, op.selection, 'model selection');
      if (state.modelSelections.some((selection) => selection.selection_id === op.selection.selection_id)) {
        fail('duplicate-state', `model selection ${op.selection.selection_id} exists`);
      }
      state.modelSelections.push(op.selection);
      break;
    case 'review.open':
      requireWorld(state, op.obligation, 'review obligation');
      if (op.obligation.state !== 'open') fail('illegal-initial-state', 'a new review obligation must be open');
      requireUnique(state.reviews, op.obligation.obligation_id, `review ${op.obligation.obligation_id}`);
      state.reviews.set(op.obligation.obligation_id, op.obligation);
      break;
    case 'review.resolve': {
      const current = requireValue(state.reviews, op.obligation_id, `review ${op.obligation_id}`);
      if (current.state !== 'open') fail('illegal-transition', `review ${op.obligation_id} is ${current.state}`);
      state.reviews.set(op.obligation_id, {
        ...current,
        state: op.resolution,
        resolved_at: op.resolved_at,
      });
      break;
    }
    case 'record.action.append':
      requireWorld(state, op.entry, 'action record');
      if (state.actionRecords.some((entry) => entry.entry_id === op.entry.entry_id)) {
        fail('duplicate-state', `action record ${op.entry.entry_id} exists`);
      }
      {
        const ruling = requireValue(
          state.rulings,
          op.entry.admissibility_decision.ruling_id,
          `ruling ${op.entry.admissibility_decision.ruling_id}`,
        );
        const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
        const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
        if (
          proposal === undefined ||
          op.entry.proposed_action !== proposal.proposed_action ||
          op.entry.admissibility_decision.verdict !== ruling.verdict ||
          op.entry.policy_model_version.policy_version !== ruling.policy_version ||
          op.entry.policy_model_version.policy_content_digest !== ruling.policy_content_digest ||
          op.entry.policy_model_version.evaluator_build_id !== ruling.evaluator_build_id ||
          op.entry.policy_model_version.acting_model_requested_id !== proposal.acting_model.requested_id ||
          op.entry.policy_model_version.acting_model_served_id !== proposal.acting_model.served_id
        ) {
          fail('record-mismatch', `action record ${op.entry.entry_id} differs from its ruling or proposal`);
        }
        const commitmentEvent = op.entry.commitment_and_effect;
        if (commitmentEvent?.event === 'commitment') {
          const commitment = requireValue(
            state.commitments,
            commitmentEvent.commitment_id,
            `commitment ${commitmentEvent.commitment_id}`,
          );
          if (
            commitment.ruling_id !== ruling.ruling_id ||
            commitment.effect_id !== commitmentEvent.effect_id ||
            commitment.idempotency_key !== commitmentEvent.idempotency_key ||
            commitment.effect_request_digest !== commitmentEvent.effect_request_digest
          ) {
            fail('record-mismatch', `action record ${op.entry.entry_id} differs from its commitment`);
          }
        }
        if (op.entry.human_intervention_event?.event === 'human_intervention_event') {
          requireValue(
            state.escalations,
            op.entry.human_intervention_event.escalation_id,
            `escalation ${op.entry.human_intervention_event.escalation_id}`,
          );
        }
        state.actionRecords.push(op.entry);
      }
      break;
    case 'record.access.append': {
      requireWorld(state, op.entry, 'access record');
      const entryId = recordAccessId(op.entry);
      if (state.accessRecords.some((entry) => recordAccessId(entry) === entryId)) {
        fail('duplicate-state', `access record ${entryId} exists`);
      }
      state.accessRecords.push(op.entry);
      break;
    }
  }
}

export function applyWorldTransaction(state: WorldState, ops: readonly WalOp[], timestamp: string): void {
  if (state.lastTimestamp !== undefined && timestamp < state.lastTimestamp) {
    fail('clock-regression', `transaction timestamp ${timestamp} precedes ${state.lastTimestamp}`);
  }
  for (const op of ops) applyWorldOp(state, op, timestamp);
  state.lastTimestamp = timestamp;
  validateWorldState(state);
}

export function validateWorldState(state: WorldState): void {
  if (state.policy !== undefined && state.policy.world_id !== state.worldId) {
    fail('world-mismatch', `policy activation belongs to ${state.policy.world_id}, not ${state.worldId}`);
  }
  for (const nonce of state.nonces.values()) {
    const ruling = state.rulings.get(nonce.ruling_id);
    if (ruling === undefined || ruling.binding.nonce !== nonce.nonce_id) {
      fail('orphan-state', `nonce ${nonce.nonce_id} has no owning ruling`);
    }
  }
  for (const reservation of state.reservations.values()) {
    const ruling = state.rulings.get(reservation.ruling_id);
    const binding = ruling?.counter_reservations.find((item) => item.id === reservation.reservation_id);
    if (
      ruling === undefined ||
      binding === undefined ||
      binding.counter !== reservation.counter ||
      binding.delta !== reservation.delta
    ) {
      fail('orphan-state', `reservation ${reservation.reservation_id} has no matching owning ruling`);
    }
  }
  for (const ruling of state.rulings.values()) {
    const nonce = state.nonces.get(ruling.binding.nonce);
    if (ruling.status === 'issued') {
      if (nonce?.state !== 'issued') fail('illegal-transition', `issued ruling ${ruling.ruling_id} has no issued nonce`);
      for (const reservation of ruling.counter_reservations) {
        if (state.reservations.get(reservation.id)?.state !== 'reserved') {
          fail('illegal-transition', `issued ruling ${ruling.ruling_id} has a non-reserved counter`);
        }
      }
    }
    if (ruling.status === 'consumed') {
      if (nonce?.state !== 'consumed') fail('illegal-transition', `consumed ruling ${ruling.ruling_id} has no consumed nonce`);
      if (![...state.commitments.values()].some((commitment) => commitment.ruling_id === ruling.ruling_id)) {
        fail('illegal-transition', `consumed ruling ${ruling.ruling_id} has no commitment`);
      }
    }
    if (ruling.status !== 'issued') continue;
    if (
      state.policy === undefined ||
      ruling.policy_version !== state.policy.policy_version ||
      ruling.policy_content_digest !== state.policy.policy_content_digest ||
      ruling.evaluator_build_id !== state.policy.evaluator_build_id
    ) {
      fail('stale-issued-ruling', `issued ruling ${ruling.ruling_id} is bound to a non-current policy`);
    }
    if (ruling.verdict === 'deny') continue;
    const mandateStatus = state.mandateStatus.get(ruling.binding.mandate_id);
    if (
      mandateStatus === undefined ||
      mandateStatus.state !== 'active' ||
      mandateStatus.version !== ruling.binding.mandate_version
    ) {
      fail('stale-issued-ruling', `issued ruling ${ruling.ruling_id} is bound to a non-current mandate`);
    }
  }
}

export function counterValue(
  state: WorldState,
  mandateId: string,
  counter: ReservationRecord['counter'],
  at?: string,
): number {
  if (counter === 'escalation_pattern') {
    return state.patternEvents.filter((event) => event.mandate_id === mandateId).length;
  }
  let value = 0;
  const day = at?.slice(0, 10);
  for (const reservation of state.reservations.values()) {
    if (reservation.mandate_id !== mandateId || reservation.counter !== counter) continue;
    if (counter === 'actions' && day !== undefined && reservation.reserved_at.slice(0, 10) !== day) continue;
    if (reservation.delta > 0 && ['reserved', 'settled', 'held_for_reconciliation'].includes(reservation.state)) {
      value += reservation.delta;
    } else if (reservation.delta < 0 && reservation.state === 'settled') {
      value += reservation.delta;
    }
  }
  return value;
}

export function currentMandate(state: WorldState, mandateId: string): Mandate | undefined {
  const status = state.mandateStatus.get(mandateId);
  return status === undefined ? undefined : state.mandates.get(mandateVersionKey(mandateId, status.version));
}
