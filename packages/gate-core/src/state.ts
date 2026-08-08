// SPDX-License-Identifier: AGPL-3.0-only
/** Deterministic replay state and the sole mutation path for WAL operations. */
import type { z } from 'zod';

import { canonicalize } from './canonicalize.js';
import { digestFor, verifyDigest } from './hash.js';
import type {
  CaseSessionHandoffRecord,
  CaseSessionProvenanceReceipt,
  CommitmentRecord,
  ConversationStoreEntry,
  ConversationIngressEvent,
  EffectRecord,
  EscalationRecord,
  FrozenProposal,
  GateRuling,
  Mandate,
  ModelCallRecord,
  ModelSelectionCheckRecord,
  ModelSelectionObservation,
  ModelSelectionTransition,
  NonceRecord,
  OutputReleaseRecord,
  PatternEvent,
  PolicyActivation,
  ProposalIntakeRecord,
  ProposalOriginRecord,
  RecordEntry,
  ReservationRecord,
  ReviewObligation,
  SystemUseDecisionRecord,
  SystemUseDecisionStatus,
  WalOp,
} from './schemas/index.js';
import type { accessChainEntry } from './schemas/record.js';
import { modelCallRecord } from './schemas/modelCall.js';
import { proposalIntakeRecord } from './schemas/proposalIntake.js';
import {
  CASE_OFFICER_MESSAGE_PROFILE,
  outputReleaseRecord,
} from './schemas/conversationTransport.js';
import { systemUseDecisionRecord } from './schemas/systemUseDecision.js';
import { systemUseDecisionDigest } from './systemUseDecision.js';

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

export interface SystemUseDecisionRuntimeStatus {
  readonly status: SystemUseDecisionStatus;
  readonly changed_at: string;
}

export interface WorldState {
  readonly worldId: string;
  lastTimestamp: string | undefined;
  readonly mandates: Map<string, Mandate>;
  readonly mandateStatus: Map<string, MandateRuntimeStatus>;
  readonly proposals: Map<string, FrozenProposal>;
  readonly proposalByHash: Map<string, string>;
  readonly proposalOrigins: Map<string, ProposalOriginRecord>;
  readonly proposalIntakes: Map<string, ProposalIntakeRecord>;
  readonly proposalIntakeByRun: Map<string, string>;
  readonly systemUseDecisions: Map<string, SystemUseDecisionRecord>;
  readonly systemUseDecisionStatus: Map<string, SystemUseDecisionRuntimeStatus>;
  readonly caseSessionHandoffs: Map<string, CaseSessionHandoffRecord>;
  readonly caseSessionProvenance: Map<string, CaseSessionProvenanceReceipt>;
  readonly nonces: Map<string, NonceRecord>;
  readonly reservations: Map<string, ReservationRecord>;
  readonly rulings: Map<string, GateRuling>;
  readonly commitments: Map<string, CommitmentRecord>;
  readonly effects: Map<string, EffectRecord>;
  readonly effectByIdempotencyKey: Map<string, string>;
  readonly escalations: Map<string, EscalationRecord>;
  readonly storeItems: Map<string, ConversationStoreEntry>;
  readonly conversationEvents: Map<string, ConversationIngressEvent>;
  readonly conversationVersionByCase: Map<string, number>;
  readonly patternEvents: PatternEvent[];
  readonly modelSelectionChecks: Map<string, ModelSelectionCheckRecord>;
  readonly modelSelections: Map<string, ModelSelectionTransition>;
  readonly currentModelSelectionByCase: Map<string, string>;
  readonly modelSelectionObservations: Map<string, ModelSelectionObservation>;
  readonly modelCalls: Map<string, ModelCallRecord>;
  readonly outputReleases: Map<string, OutputReleaseRecord>;
  readonly reviews: Map<string, ReviewObligation>;
  readonly actionRecords: RecordEntry[];
  readonly accessRecords: AccessChainValue[];
  policy: PolicyActivation | undefined;
}

export function mandateVersionKey(mandateId: string, version: number): string {
  return `${mandateId}@${version}`;
}

export function systemUseDecisionVersionKey(decisionId: string, version: number): string {
  return `${decisionId}@${version}`;
}

export function createWorldState(worldId: string): WorldState {
  return {
    worldId,
    lastTimestamp: undefined,
    mandates: new Map(),
    mandateStatus: new Map(),
    proposals: new Map(),
    proposalByHash: new Map(),
    proposalOrigins: new Map(),
    proposalIntakes: new Map(),
    proposalIntakeByRun: new Map(),
    systemUseDecisions: new Map(),
    systemUseDecisionStatus: new Map(),
    caseSessionHandoffs: new Map(),
    caseSessionProvenance: new Map(),
    nonces: new Map(),
    reservations: new Map(),
    rulings: new Map(),
    commitments: new Map(),
    effects: new Map(),
    effectByIdempotencyKey: new Map(),
    escalations: new Map(),
    storeItems: new Map(),
    conversationEvents: new Map(),
    conversationVersionByCase: new Map(),
    patternEvents: [],
    modelSelectionChecks: new Map(),
    modelSelections: new Map(),
    currentModelSelectionByCase: new Map(),
    modelSelectionObservations: new Map(),
    modelCalls: new Map(),
    outputReleases: new Map(),
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
    proposalOrigins: new Map(state.proposalOrigins),
    proposalIntakes: new Map(state.proposalIntakes),
    proposalIntakeByRun: new Map(state.proposalIntakeByRun),
    systemUseDecisions: new Map(state.systemUseDecisions),
    systemUseDecisionStatus: new Map(state.systemUseDecisionStatus),
    caseSessionHandoffs: new Map(state.caseSessionHandoffs),
    caseSessionProvenance: new Map(state.caseSessionProvenance),
    nonces: new Map(state.nonces),
    reservations: new Map(state.reservations),
    rulings: new Map(state.rulings),
    commitments: new Map(state.commitments),
    effects: new Map(state.effects),
    effectByIdempotencyKey: new Map(state.effectByIdempotencyKey),
    escalations: new Map(state.escalations),
    storeItems: new Map(state.storeItems),
    conversationEvents: new Map(state.conversationEvents),
    conversationVersionByCase: new Map(state.conversationVersionByCase),
    patternEvents: [...state.patternEvents],
    modelSelectionChecks: new Map(state.modelSelectionChecks),
    modelSelections: new Map(state.modelSelections),
    currentModelSelectionByCase: new Map(state.currentModelSelectionByCase),
    modelSelectionObservations: new Map(state.modelSelectionObservations),
    modelCalls: new Map(state.modelCalls),
    outputReleases: new Map(state.outputReleases),
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
    case 'system_use_decision.issue': {
      requireWorld(state, op.decision, 'system-use decision');
      const decision = systemUseDecisionRecord.parse(op.decision);
      if (!verifyDigest(decision.trace.record_digest, systemUseDecisionDigest(decision))) {
        fail('system-use-integrity', `system-use decision ${decision.decision_id}@${decision.version} has the wrong digest`);
      }
      const existing = [...state.systemUseDecisions.values()];
      if (existing.some((candidate) => candidate.decision_id !== decision.decision_id)) {
        fail('system-use-ambiguous', 'the bounded POC permits one system-use decision lineage per world');
      }
      const key = systemUseDecisionVersionKey(decision.decision_id, decision.version);
      requireUnique(state.systemUseDecisions, key, `system-use decision ${key}`);
      const priorVersions = existing
        .filter((candidate) => candidate.decision_id === decision.decision_id)
        .map((candidate) => candidate.version)
        .sort((left, right) => left - right);
      if (priorVersions.length === 0) {
        if (decision.version !== 1 || decision.trace.supersedes !== null) {
          fail('system-use-version', 'the first system-use decision must be version 1 without a predecessor');
        }
      } else {
        const priorVersion = priorVersions.at(-1) as number;
        if (
          decision.version !== priorVersion + 1 ||
          decision.trace.supersedes?.decision_id !== decision.decision_id ||
          decision.trace.supersedes.version !== priorVersion
        ) {
          fail('system-use-version', 'a system-use successor must be contiguous and name its predecessor');
        }
        const priorStatus = state.systemUseDecisionStatus.get(systemUseDecisionVersionKey(decision.decision_id, priorVersion));
        if (priorStatus?.status !== 'superseded') {
          fail('system-use-predecessor', 'a successor requires its predecessor to be superseded in the same or prior transaction');
        }
      }
      state.systemUseDecisions.set(key, decision);
      state.systemUseDecisionStatus.set(key, { status: decision.decision.status, changed_at: decision.trace.created_at });
      break;
    }
    case 'system_use_decision.transition': {
      const key = systemUseDecisionVersionKey(op.decision_id, op.version);
      const current = requireValue(state.systemUseDecisionStatus, key, `system-use decision ${key}`);
      const allowed: Record<SystemUseDecisionStatus, readonly SystemUseDecisionStatus[]> = {
        proposed: ['approved', 'approved_with_conditions', 'rejected'],
        approved: ['superseded', 'suspended', 'withdrawn', 'expired'],
        approved_with_conditions: ['superseded', 'suspended', 'withdrawn', 'expired'],
        rejected: [],
        superseded: [],
        suspended: [],
        withdrawn: [],
        expired: [],
      };
      if (!allowed[current.status].includes(op.status)) {
        fail('illegal-transition', `system-use decision ${key}: ${current.status} -> ${op.status}`);
      }
      if (op.changed_at < current.changed_at) fail('clock-regression', `system-use decision ${key} changed backwards in time`);
      state.systemUseDecisionStatus.set(key, { status: op.status, changed_at: op.changed_at });
      break;
    }
    case 'proposal.freeze': {
      requireWorld(state, op.proposal, 'proposal');
      requireUnique(state.proposals, op.proposal.proposal_id, `proposal ${op.proposal.proposal_id}`);
      const selection = requireValue(
        state.modelSelections,
        op.proposal.selection_id,
        `model selection ${op.proposal.selection_id}`,
      );
      if (
        state.currentModelSelectionByCase.get(selection.case_id) !== selection.selection_id ||
        selection.mandate_id !== op.proposal.mandate_ref.mandate_id ||
        selection.mandate_version !== op.proposal.mandate_ref.version ||
        selection.target.card_id !== op.proposal.acting_model.card_id ||
        selection.target.card_version !== op.proposal.acting_model.card_version ||
        selection.target.requested_id !== op.proposal.acting_model.requested_id
      ) {
        fail('binding-mismatch', `proposal ${op.proposal.proposal_id} is not bound to the current model selection`);
      }
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
    case 'proposal_origin.put': {
      requireWorld(state, op.origin, 'proposal origin');
      requireUnique(state.proposalOrigins, op.origin.proposal_id, `proposal origin ${op.origin.proposal_id}`);
      const proposal = requireValue(state.proposals, op.origin.proposal_id, `proposal ${op.origin.proposal_id}`);
      const intakeId = state.proposalIntakeByRun.get(op.origin.proposal_run_id);
      const intake = intakeId === undefined ? undefined : state.proposalIntakes.get(intakeId);
      const selection = state.modelSelections.get(op.origin.selection_id);
      const mandate = state.mandates.get(mandateVersionKey(op.origin.mandate_id, op.origin.mandate_version));
      if (
        proposal.proposal_hash !== op.origin.proposal_hash ||
        proposal.revision !== 1 ||
        proposal.created_at !== op.origin.frozen_at ||
        proposal.selection_id !== op.origin.selection_id ||
        proposal.mandate_ref.mandate_id !== op.origin.mandate_id ||
        proposal.mandate_ref.version !== op.origin.mandate_version ||
        proposal.acting_model.card_id !== op.origin.card_id ||
        proposal.acting_model.card_version !== op.origin.card_version ||
        proposal.acting_model.requested_id !== op.origin.requested_id ||
        proposal.acting_model.served_id !== op.origin.served_id ||
        selection === undefined ||
        selection.target.card_id !== op.origin.card_id ||
        selection.target.card_version !== op.origin.card_version ||
        selection.target.requested_id !== op.origin.requested_id ||
        selection.target.card_digest !== op.origin.card_digest ||
        selection.target.verifying_key_id !== op.origin.verifying_key_id ||
        mandate === undefined ||
        mandate.connected_service !== op.origin.service ||
        mandate.action_class !== op.origin.action_class ||
        state.policy === undefined ||
        state.policy.evaluator_build_id !== op.origin.evaluator_build_id ||
        intake === undefined ||
        intake.state !== 'issued' ||
        intake.call_id !== op.origin.call_id ||
        intake.case_id !== op.origin.case_id ||
        intake.session_id !== op.origin.session_id ||
        intake.authorization_boot_id !== op.origin.authorization_boot_id ||
        intake.conversation_version !== op.origin.conversation_version ||
        intake.selection_id !== op.origin.selection_id ||
        intake.mandate_id !== op.origin.mandate_id ||
        intake.mandate_version !== op.origin.mandate_version ||
        intake.card_id !== op.origin.card_id ||
        intake.card_version !== op.origin.card_version ||
        intake.requested_id !== op.origin.requested_id ||
        intake.served_id !== op.origin.served_id ||
        intake.projection_digest !== op.origin.projection_digest ||
        intake.output_digest !== op.origin.output_digest ||
        canonicalize(intake.projection_item_ids) !== canonicalize(op.origin.projection_item_ids) ||
        canonicalize(intake.system_use_decision) !== canonicalize(op.origin.system_use_decision) ||
        intake.policy_version !== op.origin.policy_version ||
        intake.policy_content_digest !== op.origin.policy_content_digest ||
        op.origin.frozen_at !== transactionTimestamp
      ) {
        fail('binding-mismatch', `proposal origin ${op.origin.proposal_id} differs from its intake or proposal`);
      }
      state.proposalOrigins.set(op.origin.proposal_id, op.origin);
      break;
    }
    case 'proposal_intake.issue': {
      requireWorld(state, op.intake, 'proposal intake');
      if (
        op.intake.state !== 'issued' ||
        op.intake.issued_at !== transactionTimestamp ||
        op.intake.state_changed_at !== transactionTimestamp ||
        op.intake.proposal_id !== null ||
        op.intake.refusal_reason !== null
      ) {
        fail('illegal-initial-state', 'a new proposal intake must be issued now without a terminal result');
      }
      requireUnique(state.proposalIntakes, op.intake.proposal_intake_id, `proposal intake ${op.intake.proposal_intake_id}`);
      if (state.proposalIntakeByRun.has(op.intake.proposal_run_id)) {
        fail('duplicate-state', `proposal run ${op.intake.proposal_run_id} already has an intake`);
      }
      if ([...state.proposalIntakes.values()].some((candidate) => candidate.call_id === op.intake.call_id)) {
        fail('duplicate-state', `model call ${op.intake.call_id} already has a proposal intake`);
      }
      const call = requireValue(state.modelCalls, op.intake.call_id, `model call ${op.intake.call_id}`);
      const binding = call.proposal_binding;
      const receipt = state.caseSessionProvenance.get(op.intake.session_id);
      if (
        call.state !== 'terminal' ||
        call.outcome !== 'admitted' ||
        call.ingress_binding !== null ||
        binding === null ||
        binding.proposal_run_id !== op.intake.proposal_run_id ||
        binding.conversation_version !== op.intake.conversation_version ||
        binding.proposal_schema_digest !== op.intake.proposal_schema_digest ||
        call.authorization_boot_id !== op.intake.authorization_boot_id ||
        call.case_id !== op.intake.case_id ||
        call.session_id !== op.intake.session_id ||
        call.selection_id !== op.intake.selection_id ||
        call.mandate_id !== op.intake.mandate_id ||
        call.mandate_version !== op.intake.mandate_version ||
        call.card_id !== op.intake.card_id ||
        call.card_version !== op.intake.card_version ||
        call.requested_id !== op.intake.requested_id ||
        call.served_id !== op.intake.served_id ||
        call.output_digest !== op.intake.output_digest ||
        call.projection_digest !== op.intake.projection_digest ||
        canonicalize(call.projection_item_ids) !== canonicalize(op.intake.projection_item_ids) ||
        canonicalize(call.system_use_decision) !== canonicalize(op.intake.system_use_decision) ||
        state.policy === undefined ||
        state.policy.policy_version !== op.intake.policy_version ||
        state.policy.policy_content_digest !== op.intake.policy_content_digest ||
        receipt === undefined ||
        receipt.state !== 'active' ||
        receipt.case_id !== op.intake.case_id ||
        receipt.authorization_boot_id !== op.intake.authorization_boot_id ||
        transactionTimestamp >= receipt.expires_at
      ) {
        fail('binding-mismatch', `proposal intake ${op.intake.proposal_intake_id} differs from its admitted call`);
      }
      state.proposalIntakes.set(op.intake.proposal_intake_id, op.intake);
      state.proposalIntakeByRun.set(op.intake.proposal_run_id, op.intake.proposal_intake_id);
      break;
    }
    case 'proposal_intake.consume': {
      const current = requireValue(
        state.proposalIntakes,
        op.proposal_intake_id,
        `proposal intake ${op.proposal_intake_id}`,
      );
      const proposal = requireValue(state.proposals, op.proposal_id, `proposal ${op.proposal_id}`);
      const origin = requireValue(state.proposalOrigins, op.proposal_id, `proposal origin ${op.proposal_id}`);
      if (
        current.state !== 'issued' ||
        op.changed_at !== transactionTimestamp ||
        transactionTimestamp >= current.expires_at ||
        origin.proposal_run_id !== current.proposal_run_id ||
        origin.call_id !== current.call_id ||
        proposal.proposal_hash !== origin.proposal_hash
      ) {
        fail('illegal-transition', `proposal intake ${op.proposal_intake_id} cannot be consumed`);
      }
      state.proposalIntakes.set(
        op.proposal_intake_id,
        proposalIntakeRecord.parse({
          ...current,
          state: 'consumed',
          state_changed_at: op.changed_at,
          proposal_id: op.proposal_id,
        }),
      );
      break;
    }
    case 'proposal_intake.refuse':
    case 'proposal_intake.invalidate': {
      const current = requireValue(
        state.proposalIntakes,
        op.proposal_intake_id,
        `proposal intake ${op.proposal_intake_id}`,
      );
      if (current.state !== 'issued' || op.changed_at !== transactionTimestamp) {
        fail('illegal-transition', `proposal intake ${op.proposal_intake_id} cannot become terminal`);
      }
      state.proposalIntakes.set(
        op.proposal_intake_id,
        proposalIntakeRecord.parse({
          ...current,
          state: op.op === 'proposal_intake.refuse' ? 'refused' : 'invalidated',
          state_changed_at: op.changed_at,
          refusal_reason: op.reason,
        }),
      );
      break;
    }
    case 'proposal_intake.expire': {
      const current = requireValue(
        state.proposalIntakes,
        op.proposal_intake_id,
        `proposal intake ${op.proposal_intake_id}`,
      );
      if (
        current.state !== 'issued' ||
        op.changed_at !== transactionTimestamp ||
        (current.expires_at > op.changed_at && current.authorization_boot_id === op.authorization_boot_id)
      ) {
        fail('illegal-transition', `proposal intake ${op.proposal_intake_id} cannot expire`);
      }
      state.proposalIntakes.set(
        op.proposal_intake_id,
        proposalIntakeRecord.parse({ ...current, state: 'expired', state_changed_at: op.changed_at }),
      );
      break;
    }
    case 'case_session_handoff.issue': {
      requireWorld(state, op.handoff, 'case-session handoff');
      if (op.handoff.state !== 'issued' || op.handoff.consumed_at !== null) {
        fail('illegal-initial-state', 'a new case-session handoff must be issued and unconsumed');
      }
      requireUnique(
        state.caseSessionHandoffs,
        op.handoff.handoff_id,
        `case-session handoff ${op.handoff.handoff_id}`,
      );
      state.caseSessionHandoffs.set(op.handoff.handoff_id, op.handoff);
      break;
    }
    case 'case_session_handoff.consume': {
      const current = requireValue(
        state.caseSessionHandoffs,
        op.handoff_id,
        `case-session handoff ${op.handoff_id}`,
      );
      if (current.state !== 'issued') {
        fail('illegal-transition', `case-session handoff ${op.handoff_id}: ${current.state} -> consumed`);
      }
      if (op.consumed_at !== transactionTimestamp) {
        fail('binding-mismatch', 'handoff consumption must use the transaction timestamp');
      }
      state.caseSessionHandoffs.set(op.handoff_id, {
        ...current,
        state: 'consumed',
        consumed_at: op.consumed_at,
      });
      break;
    }
    case 'case_session_handoff.expire': {
      const current = requireValue(
        state.caseSessionHandoffs,
        op.handoff_id,
        `case-session handoff ${op.handoff_id}`,
      );
      if (current.state !== 'issued') {
        fail('illegal-transition', `case-session handoff ${op.handoff_id}: ${current.state} -> expired`);
      }
      state.caseSessionHandoffs.set(op.handoff_id, { ...current, state: 'expired' });
      break;
    }
    case 'case_session_provenance.issue': {
      requireWorld(state, op.receipt, 'case-session provenance receipt');
      if (op.receipt.state !== 'active' || op.receipt.issued_at !== transactionTimestamp) {
        fail('illegal-initial-state', 'a new case-session provenance receipt must be active and issued now');
      }
      if (state.caseSessionProvenance.get(op.receipt.session_id)?.state === 'active') {
        fail('duplicate-state', `active case-session provenance receipt ${op.receipt.session_id} already exists`);
      }
      state.caseSessionProvenance.set(op.receipt.session_id, op.receipt);
      break;
    }
    case 'case_session_provenance.expire': {
      const current = requireValue(
        state.caseSessionProvenance,
        op.session_id,
        `case-session provenance receipt ${op.session_id}`,
      );
      if (current.state !== 'active') {
        fail('illegal-transition', `case-session provenance receipt ${op.session_id}: ${current.state} -> expired`);
      }
      state.caseSessionProvenance.set(op.session_id, { ...current, state: 'expired' });
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
      if (
        proposal.acting_model.requested_id !== op.ruling.binding.acting_model_id ||
        proposal.selection_id !== op.ruling.binding.selection_id
      ) {
        fail('binding-mismatch', `ruling ${op.ruling.ruling_id} differs from its proposal model`);
      }
      const currentSelection = state.modelSelections.get(op.ruling.binding.selection_id);
      if (
        currentSelection === undefined ||
        state.currentModelSelectionByCase.get(currentSelection.case_id) !== currentSelection.selection_id
      ) {
        fail('binding-mismatch', `ruling ${op.ruling.ruling_id} is not bound to the current model selection`);
      }
      if (
        op.ruling.verdict !== 'deny' &&
        (currentSelection.target.card_digest !== op.ruling.binding.card_digest ||
          currentSelection.target.verifying_key_id !== op.ruling.binding.card_key_id ||
          canonicalize(currentSelection.system_use_decision) !== canonicalize(op.ruling.binding.system_use_decision))
      ) {
        fail('binding-mismatch', `ruling ${op.ruling.ruling_id} differs from the current model selection evidence`);
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
      const effect = state.effects.get(current.effect_id);
      if (op.resolution === 'success' || op.resolution === 'failed') {
        if (effect === undefined || effect.outcome !== op.resolution) {
          fail('binding-mismatch', `commitment ${op.commitment_id} has no matching durable effect outcome`);
        }
      } else if (op.resolution === 'no-effect' && effect !== undefined) {
        fail('binding-mismatch', `commitment ${op.commitment_id} already has a durable effect outcome`);
      }
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
    case 'escalation.link_successor': {
      const current = requireValue(state.escalations, op.escalation_id, `escalation ${op.escalation_id}`);
      requireValue(state.rulings, op.successor_ruling_id, `successor ruling ${op.successor_ruling_id}`);
      if (current.state !== 'disposed') {
        fail('illegal-transition', `escalation ${op.escalation_id} must be disposed before linking a successor`);
      }
      if (current.successor_ruling_id !== null) {
        fail('illegal-transition', `escalation ${op.escalation_id} already has a successor`);
      }
      state.escalations.set(op.escalation_id, { ...current, successor_ruling_id: op.successor_ruling_id });
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
        commitment.effect_request_digest !== op.effect.effect_request_digest ||
        commitment.services_ledger_id !== op.effect.services_ledger_id
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
      requireWorld(state, op.entry, 'conversation store entry');
      requireUnique(state.storeItems, op.entry.item.id, `store item ${op.entry.item.id}`);
      state.storeItems.set(op.entry.item.id, op.entry);
      break;
    case 'store.remove': {
      const current = requireValue(state.storeItems, op.item_id, `store item ${op.item_id}`);
      if (current.case_id !== op.case_id) {
        fail('case-mismatch', `store item ${op.item_id} belongs to ${current.case_id}, not ${op.case_id}`);
      }
      state.storeItems.delete(op.item_id);
      break;
    }
    case 'conversation.event.append': {
      requireWorld(state, op.event, 'conversation ingress event');
      requireUnique(state.conversationEvents, op.event.event_id, `conversation event ${op.event.event_id}`);
      const entry = requireValue(state.storeItems, op.event.item_id, `store item ${op.event.item_id}`);
      if (
        entry.case_id !== op.event.case_id ||
        entry.item.turn !== op.event.turn_id ||
        op.event.conversation_version !== (state.conversationVersionByCase.get(op.event.case_id) ?? 0) + 1 ||
        !verifyDigest(
          op.event.content_digest,
          digestFor('conversation-item-content', {
            case_id: op.event.case_id,
            item_id: op.event.item_id,
            text: entry.item.text,
          }),
        ) ||
        Buffer.byteLength(entry.item.text, 'utf8') !== op.event.byte_length ||
        (op.event.kind === 'message_ingress' &&
          (entry.item.store !== 'said' ||
            entry.item.origin_actor !== 'officer' ||
            !verifyDigest(
              op.event.ingress_profile_digest,
              digestFor('conversation-ingress-profile', CASE_OFFICER_MESSAGE_PROFILE),
            ) ||
            canonicalize(entry.item.tags) !== canonicalize(CASE_OFFICER_MESSAGE_PROFILE.tags) ||
            canonicalize(entry.item.provenance) !== canonicalize(CASE_OFFICER_MESSAGE_PROFILE.provenance))) ||
        (op.event.kind === 'model_output_ingress' &&
          (entry.item.store !== 'inferred' || entry.item.origin_actor !== undefined))
      ) {
        fail('binding-mismatch', `conversation event ${op.event.event_id} differs from its store item`);
      }
      if (
        op.event.kind === 'message_ingress' &&
        [...state.conversationEvents.values()].some(
          (event) => event.kind === 'message_ingress' && event.message_id === op.event.message_id,
        )
      ) {
        fail('duplicate-state', `conversation message ${op.event.message_id} already exists`);
      }
      if (op.event.kind === 'model_output_ingress') {
        const releaseId = op.event.release_id;
        if (
          [...state.conversationEvents.values()].some(
            (event) => event.kind === 'model_output_ingress' && event.release_id === releaseId,
          )
        ) {
          fail('duplicate-state', `output release ${releaseId} already has a conversation event`);
        }
      }
      state.conversationEvents.set(op.event.event_id, op.event);
      break;
    }
    case 'pattern.record':
      requireWorld(state, op.event, 'pattern event');
      if (state.patternEvents.some((event) => event.event_id === op.event.event_id)) {
        fail('duplicate-state', `pattern event ${op.event.event_id} exists`);
      }
      state.patternEvents.push(op.event);
      break;
    case 'model_selection_check.issue':
      requireWorld(state, op.check, 'model selection check');
      if (
        op.check.state !== 'issued' ||
        op.check.consumed_at !== null ||
        op.check.authenticated_actor !== 'proc:orchestrator' ||
        op.check.issued_at !== transactionTimestamp ||
        Date.parse(op.check.expires_at) - Date.parse(op.check.issued_at) > 300_000
      ) {
        fail(
          'illegal-initial-state',
          'a model selection check must be issued now to the orchestrator for at most five minutes',
        );
      }
      requireUnique(state.modelSelectionChecks, op.check.check_id, `model selection check ${op.check.check_id}`);
      state.modelSelectionChecks.set(op.check.check_id, op.check);
      break;
    case 'model_selection_check.consume': {
      const current = requireValue(
        state.modelSelectionChecks,
        op.check_id,
        `model selection check ${op.check_id}`,
      );
      if (current.state !== 'issued') {
        fail('illegal-transition', `model selection check ${op.check_id}: ${current.state} -> consumed`);
      }
      if (op.consumed_at !== transactionTimestamp) {
        fail('binding-mismatch', 'selection check consumption must use the transaction timestamp');
      }
      state.modelSelectionChecks.set(op.check_id, { ...current, state: 'consumed', consumed_at: op.consumed_at });
      break;
    }
    case 'model_selection_check.expire': {
      const current = requireValue(
        state.modelSelectionChecks,
        op.check_id,
        `model selection check ${op.check_id}`,
      );
      if (current.state !== 'issued') {
        fail('illegal-transition', `model selection check ${op.check_id}: ${current.state} -> expired`);
      }
      state.modelSelectionChecks.set(op.check_id, { ...current, state: 'expired' });
      break;
    }
    case 'model_selection.append': {
      requireWorld(state, op.selection, 'model selection');
      requireUnique(state.modelSelections, op.selection.selection_id, `model selection ${op.selection.selection_id}`);
      const check = requireValue(
        state.modelSelectionChecks,
        op.selection.check_id,
        `model selection check ${op.selection.check_id}`,
      );
      const currentId = state.currentModelSelectionByCase.get(op.selection.case_id) ?? null;
      if (
        check.state !== 'consumed' ||
        check.case_id !== op.selection.case_id ||
        check.expected_current_selection_id !== op.selection.predecessor_selection_id ||
        currentId !== op.selection.predecessor_selection_id ||
        check.mandate_id !== op.selection.mandate_id ||
        check.mandate_version !== op.selection.mandate_version ||
        canonicalize(check.target) !== canonicalize(op.selection.target) ||
        canonicalize(check.system_use_decision) !== canonicalize(op.selection.system_use_decision) ||
        state.policy === undefined ||
        state.policy.policy_version !== check.policy_version ||
        state.policy.policy_content_digest !== check.policy_content_digest ||
        state.policy.evaluator_build_id !== check.evaluator_build_id ||
        op.selection.selected_at !== transactionTimestamp
      ) {
        fail('binding-mismatch', `model selection ${op.selection.selection_id} differs from its consumed check`);
      }
      state.modelSelections.set(op.selection.selection_id, op.selection);
      state.currentModelSelectionByCase.set(op.selection.case_id, op.selection.selection_id);
      break;
    }
    case 'model_selection.observe': {
      requireWorld(state, op.observation, 'model selection observation');
      requireUnique(
        state.modelSelectionObservations,
        op.observation.observation_id,
        `model selection observation ${op.observation.observation_id}`,
      );
      if ([...state.modelSelectionObservations.values()].some((value) => value.call_id === op.observation.call_id)) {
        fail('duplicate-state', `model call ${op.observation.call_id} already has a selection observation`);
      }
      requireValue(state.modelSelections, op.observation.selection_id, `model selection ${op.observation.selection_id}`);
      const call = requireValue(state.modelCalls, op.observation.call_id, `model call ${op.observation.call_id}`);
      if (
        call.state !== 'terminal' ||
        call.selection_id !== op.observation.selection_id ||
        call.served_id !== op.observation.served_id ||
        call.outcome !== op.observation.terminal_outcome ||
        op.observation.observed_at !== transactionTimestamp
      ) {
        fail('binding-mismatch', `selection observation ${op.observation.observation_id} differs from its call`);
      }
      state.modelSelectionObservations.set(op.observation.observation_id, op.observation);
      break;
    }
    case 'model_call.open':
      requireWorld(state, op.call, 'model call');
      if (op.call.state !== 'open' || op.call.outcome !== 'indeterminate') {
        fail('illegal-initial-state', 'a new model call must be open and indeterminate');
      }
      requireUnique(state.modelCalls, op.call.call_id, `model call ${op.call.call_id}`);
      {
        const selection = requireValue(
          state.modelSelections,
          op.call.selection_id,
          `model selection ${op.call.selection_id}`,
        );
        if (
          state.currentModelSelectionByCase.get(op.call.case_id) !== selection.selection_id ||
          selection.case_id !== op.call.case_id ||
          selection.mandate_id !== op.call.mandate_id ||
          selection.mandate_version !== op.call.mandate_version ||
          selection.target.card_id !== op.call.card_id ||
          selection.target.card_version !== op.call.card_version ||
          selection.target.requested_id !== op.call.requested_id ||
          canonicalize(selection.system_use_decision) !== canonicalize(op.call.system_use_decision)
        ) {
          fail('binding-mismatch', `model call ${op.call.call_id} differs from its current selection`);
        }
      }
      if ([...state.modelCalls.values()].some((call) => call.case_id === op.call.case_id && call.turn_id === op.call.turn_id)) {
        fail('duplicate-state', `model turn ${op.call.turn_id} already has a call`);
      }
      // Pre-M5.10 projection-only WAL entries have no item-id array; message-bound calls never use that legacy form.
      const purposeCount = Number(op.call.ingress_binding !== null) + Number(op.call.proposal_binding !== null);
      if (
        (op.call.projection_item_count !== op.call.projection_item_ids.length &&
          !(purposeCount === 0 && op.call.projection_item_ids.length === 0)) ||
        new Set(op.call.projection_item_ids).size !== op.call.projection_item_ids.length ||
        purposeCount > 1 ||
        (purposeCount === 0) !== (op.call.session_id === null)
      ) {
        fail('binding-mismatch', `model call ${op.call.call_id} has inconsistent projection or purpose bindings`);
      }
      if (op.call.ingress_binding !== null && op.call.session_id !== null) {
        const ingress = op.call.ingress_binding;
        const event = [...state.conversationEvents.values()].find(
          (candidate) => candidate.kind === 'message_ingress' && candidate.message_id === ingress.message_id,
        );
        const receipt = state.caseSessionProvenance.get(op.call.session_id);
        if (
          event?.kind !== 'message_ingress' ||
          event.case_id !== op.call.case_id ||
          event.turn_id !== op.call.turn_id ||
          event.item_id !== ingress.message_item_id ||
          event.session_id !== op.call.session_id ||
          event.conversation_version !== ingress.conversation_version ||
          !verifyDigest(event.content_digest, ingress.message_digest) ||
          (state.conversationVersionByCase.get(op.call.case_id) ?? 0) !== ingress.conversation_version ||
          !op.call.projection_item_ids.includes(ingress.message_item_id) ||
          receipt === undefined ||
          receipt.state !== 'active' ||
          receipt.case_id !== op.call.case_id ||
          receipt.authorization_boot_id !== op.call.authorization_boot_id ||
          transactionTimestamp >= receipt.expires_at
        ) {
          fail('binding-mismatch', `model call ${op.call.call_id} has stale message ingress evidence`);
        }
      }
      if (op.call.proposal_binding !== null && op.call.session_id !== null) {
        const binding = op.call.proposal_binding;
        const receipt = state.caseSessionProvenance.get(op.call.session_id);
        if (
          binding.conversation_version !== (state.conversationVersionByCase.get(op.call.case_id) ?? 0) ||
          op.call.projection_item_ids.length === 0 ||
          receipt === undefined ||
          receipt.state !== 'active' ||
          receipt.case_id !== op.call.case_id ||
          receipt.authorization_boot_id !== op.call.authorization_boot_id ||
          transactionTimestamp >= receipt.expires_at
        ) {
          fail('binding-mismatch', `model call ${op.call.call_id} has stale proposal-purpose evidence`);
        }
      }
      state.modelCalls.set(op.call.call_id, op.call);
      break;
    case 'model_call.complete': {
      const current = requireValue(state.modelCalls, op.call_id, `model call ${op.call_id}`);
      if (current.state !== 'open') fail('illegal-transition', `model call ${op.call_id} is ${current.state}`);
      if (state.currentModelSelectionByCase.get(current.case_id) !== current.selection_id) {
        fail('stale-selection', `model call ${op.call_id} is bound to a stale selection`);
      }
      if (op.completed_at < current.opened_at) fail('clock-regression', 'model call completed before it opened');
      if (op.completed_at > current.expires_at) fail('expired-state', `model call ${op.call_id} is expired`);
      state.modelCalls.set(
        op.call_id,
        modelCallRecord.parse({
          ...current,
          state: 'terminal',
          outcome: op.outcome,
          provider_disclosure: 'confirmed',
          completed_at: op.completed_at,
          served_id: op.served_id,
          output_digest: op.output_digest,
          failure_reason: null,
        }),
      );
      break;
    }
    case 'model_call.fail': {
      const current = requireValue(state.modelCalls, op.call_id, `model call ${op.call_id}`);
      if (current.state !== 'open') fail('illegal-transition', `model call ${op.call_id} is ${current.state}`);
      if (state.currentModelSelectionByCase.get(current.case_id) !== current.selection_id) {
        fail('stale-selection', `model call ${op.call_id} is bound to a stale selection`);
      }
      if (op.completed_at < current.opened_at) fail('clock-regression', 'model call failed before it opened');
      if (op.completed_at > current.expires_at && op.failure_reason !== 'selection-invalidated') {
        fail('expired-state', `model call ${op.call_id} is expired`);
      }
      state.modelCalls.set(
        op.call_id,
        modelCallRecord.parse({
          ...current,
          state: 'terminal',
          outcome: 'failed',
          provider_disclosure: op.provider_disclosure,
          completed_at: op.completed_at,
          served_id: op.served_id,
          output_digest: null,
          failure_reason: op.failure_reason,
        }),
      );
      break;
    }
    case 'output_release.issue': {
      requireWorld(state, op.release, 'output release');
      if (
        op.release.state !== 'issued' ||
        op.release.issued_at !== transactionTimestamp ||
        op.release.state_changed_at !== transactionTimestamp ||
        op.release.consumption_result !== null ||
        op.release.invalidation_reason !== null
      ) {
        fail('illegal-initial-state', 'a new output release must be issued now without a terminal result');
      }
      requireUnique(state.outputReleases, op.release.release_id, `output release ${op.release.release_id}`);
      if ([...state.outputReleases.values()].some((release) => release.call_id === op.release.call_id)) {
        fail('duplicate-state', `model call ${op.release.call_id} already has an output release`);
      }
      const call = requireValue(state.modelCalls, op.release.call_id, `model call ${op.release.call_id}`);
      const selection = requireValue(
        state.modelSelections,
        op.release.selection_id,
        `model selection ${op.release.selection_id}`,
      );
      const ingress = call.ingress_binding;
      const receipt = state.caseSessionProvenance.get(op.release.session_id);
      const messageEvent = [...state.conversationEvents.values()].find(
        (event) => event.kind === 'message_ingress' && event.message_id === op.release.message_id,
      );
      if (
        call.state !== 'terminal' ||
        call.outcome !== 'admitted' ||
        call.authorization_boot_id !== op.release.authorization_boot_id ||
        call.case_id !== op.release.case_id ||
        call.turn_id !== op.release.turn_id ||
        call.session_id !== op.release.session_id ||
        ingress === null ||
        ingress.message_id !== op.release.message_id ||
        ingress.message_item_id !== op.release.message_item_id ||
        ingress.conversation_version !== op.release.conversation_version ||
        call.selection_id !== op.release.selection_id ||
        call.mandate_id !== op.release.mandate_id ||
        call.mandate_version !== op.release.mandate_version ||
        call.card_id !== op.release.card_id ||
        call.card_version !== op.release.card_version ||
        call.requested_id !== op.release.requested_id ||
        call.served_id !== op.release.served_id ||
        call.output_digest !== op.release.output_digest ||
        call.projection_digest !== op.release.projection_digest ||
        canonicalize(call.projection_item_ids) !== canonicalize(op.release.projection_item_ids) ||
        canonicalize(call.system_use_decision) !== canonicalize(op.release.system_use_decision) ||
        (state.conversationVersionByCase.get(op.release.case_id) ?? 0) !== op.release.conversation_version ||
        selection.case_id !== op.release.case_id ||
        selection.target.card_digest !== op.release.card_digest ||
        selection.target.verifying_key_id !== op.release.verifying_key_id ||
        state.policy === undefined ||
        state.policy.policy_version !== op.release.policy_version ||
        state.policy.policy_content_digest !== op.release.policy_content_digest ||
        state.policy.evaluator_build_id !== op.release.evaluator_build_id ||
        receipt === undefined ||
        receipt.state !== 'active' ||
        receipt.authorization_boot_id !== op.release.authorization_boot_id ||
        receipt.case_id !== op.release.case_id ||
        transactionTimestamp >= receipt.expires_at ||
        messageEvent?.kind !== 'message_ingress' ||
        messageEvent.session_id !== op.release.session_id ||
        messageEvent.item_id !== op.release.message_item_id
      ) {
        fail('binding-mismatch', `output release ${op.release.release_id} differs from its admitted call`);
      }
      state.outputReleases.set(op.release.release_id, op.release);
      break;
    }
    case 'output_release.consume': {
      const current = requireValue(state.outputReleases, op.release_id, `output release ${op.release_id}`);
      if (current.state !== 'issued') {
        fail('illegal-transition', `output release ${op.release_id}: ${current.state} -> consumed`);
      }
      if (transactionTimestamp >= current.expires_at) {
        fail('expired-state', `output release ${op.release_id} is expired`);
      }
      const event = requireValue(state.conversationEvents, op.result.event_id, `conversation event ${op.result.event_id}`);
      if (
        event.kind !== 'model_output_ingress' ||
        event.release_id !== current.release_id ||
        event.item_id !== op.result.item_id ||
        event.conversation_version !== op.result.conversation_version ||
        event.recorded_at !== op.result.recorded_at ||
        op.result.recorded_at !== transactionTimestamp ||
        op.result.conversation_version !== (state.conversationVersionByCase.get(current.case_id) ?? 0) + 1
      ) {
        fail('binding-mismatch', `output release ${op.release_id} consumption differs from its ingress event`);
      }
      state.outputReleases.set(
        op.release_id,
        outputReleaseRecord.parse({
          ...current,
          state: 'consumed',
          state_changed_at: transactionTimestamp,
          consumption_result: op.result,
        }),
      );
      break;
    }
    case 'output_release.invalidate': {
      const current = requireValue(state.outputReleases, op.release_id, `output release ${op.release_id}`);
      if (current.state !== 'issued' || op.changed_at !== transactionTimestamp) {
        fail('illegal-transition', `output release ${op.release_id}: ${current.state} -> invalidated`);
      }
      state.outputReleases.set(
        op.release_id,
        outputReleaseRecord.parse({
          ...current,
          state: 'invalidated',
          state_changed_at: op.changed_at,
          invalidation_reason: op.reason,
        }),
      );
      break;
    }
    case 'output_release.expire': {
      const current = requireValue(state.outputReleases, op.release_id, `output release ${op.release_id}`);
      if (
        current.state !== 'issued' ||
        op.changed_at !== transactionTimestamp ||
        (current.expires_at > op.changed_at && current.authorization_boot_id === op.authorization_boot_id)
      ) {
        fail('illegal-transition', `output release ${op.release_id}: ${current.state} -> expired`);
      }
      state.outputReleases.set(
        op.release_id,
        outputReleaseRecord.parse({ ...current, state: 'expired', state_changed_at: op.changed_at }),
      );
      break;
    }
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
            commitment.effect_request_digest !== commitmentEvent.effect_request_digest ||
            commitment.services_ledger_id !== commitmentEvent.services_ledger_id
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

function validateTransactionShape(state: WorldState, ops: readonly WalOp[], timestamp: string): void {
  for (const receiptOp of ops.filter(
    (op): op is Extract<WalOp, { op: 'case_session_provenance.issue' }> =>
      op.op === 'case_session_provenance.issue',
  )) {
    const consume = ops.find(
      (op): op is Extract<WalOp, { op: 'case_session_handoff.consume' }> =>
        op.op === 'case_session_handoff.consume' && op.handoff_id === receiptOp.receipt.handoff_id,
    );
    if (consume === undefined || consume.consumed_at !== timestamp) {
      fail('transaction-shape', 'case-session provenance must accompany handoff consumption');
    }
  }
  for (const releaseOp of ops.filter(
    (op): op is Extract<WalOp, { op: 'output_release.issue' }> => op.op === 'output_release.issue',
  )) {
    const completion = ops.find(
      (op): op is Extract<WalOp, { op: 'model_call.complete' }> =>
        op.op === 'model_call.complete' &&
        op.call_id === releaseOp.release.call_id &&
        op.outcome === 'admitted',
    );
    if (completion === undefined || completion.completed_at !== timestamp) {
      fail('transaction-shape', 'output release issue must accompany admitted model-call completion');
    }
  }
  for (const intakeOp of ops.filter(
    (op): op is Extract<WalOp, { op: 'proposal_intake.issue' }> => op.op === 'proposal_intake.issue',
  )) {
    const completion = ops.find(
      (op): op is Extract<WalOp, { op: 'model_call.complete' }> =>
        op.op === 'model_call.complete' &&
        op.call_id === intakeOp.intake.call_id &&
        op.outcome === 'admitted',
    );
    if (completion === undefined || completion.completed_at !== timestamp) {
      fail('transaction-shape', 'proposal intake issue must accompany admitted model-call completion');
    }
  }
  for (const completion of ops.filter(
    (op): op is Extract<WalOp, { op: 'model_call.complete' }> =>
      op.op === 'model_call.complete' && op.outcome === 'admitted',
  )) {
    const call = state.modelCalls.get(completion.call_id);
    if (call?.state === 'open') {
      const releaseCount = ops.filter(
        (op) => op.op === 'output_release.issue' && op.release.call_id === completion.call_id,
      ).length;
      const intakeCount = ops.filter(
        (op) => op.op === 'proposal_intake.issue' && op.intake.call_id === completion.call_id,
      ).length;
      if (
        (call.ingress_binding !== null && (releaseCount !== 1 || intakeCount !== 0)) ||
        (call.proposal_binding !== null && (intakeCount !== 1 || releaseCount !== 0)) ||
        (call.ingress_binding === null && call.proposal_binding === null && (releaseCount !== 0 || intakeCount !== 0))
      ) {
        fail('transaction-shape', 'admitted model-call consumer does not match its purpose binding');
      }
    }
  }
  for (const consume of ops.filter(
    (op): op is Extract<WalOp, { op: 'proposal_intake.consume' }> => op.op === 'proposal_intake.consume',
  )) {
    const freeze = ops.filter(
      (op): op is Extract<WalOp, { op: 'proposal.freeze' }> =>
        op.op === 'proposal.freeze' && op.proposal.proposal_id === consume.proposal_id,
    );
    const origin = ops.filter(
      (op): op is Extract<WalOp, { op: 'proposal_origin.put' }> =>
        op.op === 'proposal_origin.put' && op.origin.proposal_id === consume.proposal_id,
    );
    if (freeze.length !== 1 || origin.length !== 1 || consume.changed_at !== timestamp) {
      fail('transaction-shape', 'proposal intake consumption must freeze one proposal with one origin');
    }
  }
  for (const eventOp of ops.filter(
    (op): op is Extract<WalOp, { op: 'conversation.event.append' }> => op.op === 'conversation.event.append',
  )) {
    if (!ops.some((op) => op.op === 'store.put' && op.entry.item.id === eventOp.event.item_id)) {
      fail('transaction-shape', 'conversation ingress event must accompany its store item');
    }
  }
  for (const consumeOp of ops.filter(
    (op): op is Extract<WalOp, { op: 'output_release.consume' }> => op.op === 'output_release.consume',
  )) {
    const event = ops.find(
      (op): op is Extract<WalOp, { op: 'conversation.event.append' }> =>
        op.op === 'conversation.event.append' &&
        op.event.kind === 'model_output_ingress' &&
        op.event.release_id === consumeOp.release_id,
    );
    if (
      event === undefined ||
      event.event.item_id !== consumeOp.result.item_id ||
      event.event.event_id !== consumeOp.result.event_id
    ) {
      fail('transaction-shape', 'output release consumption must accompany its exact ingress event');
    }
  }
  const selections = ops.filter((op): op is Extract<WalOp, { op: 'model_selection.append' }> =>
    op.op === 'model_selection.append',
  );
  if (selections.length > 1 || (selections.length === 1 && ops.at(-1) !== selections[0])) {
    fail('transaction-shape', 'a transaction may append at most one model selection, and it must be last');
  }
  for (const selectionOp of selections) {
    const consumes = ops.filter(
      (op): op is Extract<WalOp, { op: 'model_selection_check.consume' }> =>
        op.op === 'model_selection_check.consume' && op.check_id === selectionOp.selection.check_id,
    );
    if (consumes.length !== 1 || consumes[0]?.consumed_at !== timestamp) {
      fail('transaction-shape', 'a model selection must consume its check in the same transaction');
    }
  }
  for (const op of ops) {
    if (
      op.op === 'model_selection_check.consume' &&
      !selections.some((selection) => selection.selection.check_id === op.check_id)
    ) {
      fail('transaction-shape', 'a model selection check may be consumed only by its selection transaction');
    }
  }
  for (const op of ops) {
    if (op.op === 'model_call.fail' && op.failure_reason === 'selection-invalidated') {
      const call = state.modelCalls.get(op.call_id);
      const matchingSelection = selections.find(
        (candidate) =>
          candidate.selection.predecessor_selection_id === call?.selection_id &&
          candidate.selection.case_id === call?.case_id,
      );
      if (
        call === undefined ||
        matchingSelection === undefined ||
        op.provider_disclosure !== 'possible' ||
        op.served_id !== null ||
        op.completed_at !== timestamp
      ) {
        fail('transaction-shape', 'selection invalidation may occur only inside its successor switch transaction');
      }
    }
    if (op.op === 'model_selection.observe') {
      const terminal = ops.find(
        (candidate) =>
          (candidate.op === 'model_call.complete' || candidate.op === 'model_call.fail') &&
          candidate.call_id === op.observation.call_id,
      );
      if (terminal === undefined) {
        fail('transaction-shape', 'a selection observation must accompany its terminal model-call operation');
      }
    }
  }
}

export function applyWorldTransaction(state: WorldState, ops: readonly WalOp[], timestamp: string): void {
  if (state.lastTimestamp !== undefined && timestamp < state.lastTimestamp) {
    fail('clock-regression', `transaction timestamp ${timestamp} precedes ${state.lastTimestamp}`);
  }
  validateTransactionShape(state, ops, timestamp);
  const changedCases = new Set(
    ops.flatMap((op) =>
      op.op === 'store.put' ? [op.entry.case_id] : op.op === 'store.remove' ? [op.case_id] : [],
    ),
  );
  for (const op of ops) applyWorldOp(state, op, timestamp);
  for (const caseId of changedCases) {
    state.conversationVersionByCase.set(caseId, (state.conversationVersionByCase.get(caseId) ?? 0) + 1);
  }
  state.lastTimestamp = timestamp;
  validateWorldState(state);
}

export function validateWorldState(state: WorldState): void {
  if (state.policy !== undefined && state.policy.world_id !== state.worldId) {
    fail('world-mismatch', `policy activation belongs to ${state.policy.world_id}, not ${state.worldId}`);
  }
  for (const [caseId, selectionId] of state.currentModelSelectionByCase) {
    const selection = state.modelSelections.get(selectionId);
    if (selection === undefined || selection.case_id !== caseId) {
      fail('orphan-state', `case ${caseId} has no matching current model selection`);
    }
  }
  for (const call of state.modelCalls.values()) {
    if (call.state === 'open' && state.currentModelSelectionByCase.get(call.case_id) !== call.selection_id) {
      fail('stale-open-call', `open model call ${call.call_id} is bound to a stale selection`);
    }
  }
  for (const intake of state.proposalIntakes.values()) {
    const call = state.modelCalls.get(intake.call_id);
    if (
      call === undefined ||
      call.proposal_binding === null ||
      call.ingress_binding !== null ||
      call.case_id !== intake.case_id ||
      call.proposal_binding.proposal_run_id !== intake.proposal_run_id
    ) {
      fail('orphan-state', `proposal intake ${intake.proposal_intake_id} has no matching proposal-purpose call`);
    }
    if (intake.state === 'consumed') {
      const proposal = intake.proposal_id === null ? undefined : state.proposals.get(intake.proposal_id);
      const origin = intake.proposal_id === null ? undefined : state.proposalOrigins.get(intake.proposal_id);
      if (proposal === undefined || origin === undefined || proposal.proposal_hash !== origin.proposal_hash) {
        fail('orphan-state', `consumed proposal intake ${intake.proposal_intake_id} has no frozen proposal origin`);
      }
    }
  }
  for (const origin of state.proposalOrigins.values()) {
    const proposal = state.proposals.get(origin.proposal_id);
    const intakeId = state.proposalIntakeByRun.get(origin.proposal_run_id);
    const intake = intakeId === undefined ? undefined : state.proposalIntakes.get(intakeId);
    if (proposal === undefined || intake?.proposal_id !== origin.proposal_id || intake.state !== 'consumed') {
      fail('orphan-state', `proposal origin ${origin.proposal_id} has no consumed intake`);
    }
  }
  for (const receipt of state.caseSessionProvenance.values()) {
    const handoff = state.caseSessionHandoffs.get(receipt.handoff_id);
    if (
      handoff === undefined ||
      handoff.state !== 'consumed' ||
      handoff.world_id !== receipt.world_id ||
      handoff.case_id !== receipt.case_id ||
      handoff.role !== receipt.role ||
      handoff.target_origin !== receipt.target_origin ||
      handoff.authorization_boot_id !== receipt.authorization_boot_id
    ) {
      fail('orphan-state', `case-session provenance receipt ${receipt.session_id} has no matching handoff`);
    }
  }
  for (const event of state.conversationEvents.values()) {
    const item = state.storeItems.get(event.item_id);
    if (item !== undefined && item.case_id !== event.case_id) {
      fail('orphan-state', `conversation event ${event.event_id} has a cross-case store item`);
    }
  }
  for (const release of state.outputReleases.values()) {
    const call = state.modelCalls.get(release.call_id);
    if (call === undefined || call.ingress_binding === null || call.case_id !== release.case_id) {
      fail('orphan-state', `output release ${release.release_id} has no matching message-bound call`);
    }
    if (release.state === 'consumed') {
      const result = release.consumption_result;
      const event = result === null ? undefined : state.conversationEvents.get(result.event_id);
      if (result === null || event?.kind !== 'model_output_ingress' || event.release_id !== release.release_id) {
        fail('orphan-state', `consumed output release ${release.release_id} has no matching ingress event`);
      }
    }
    if (release.state === 'issued') {
      const mandateStatus = state.mandateStatus.get(release.mandate_id);
      if (
        state.currentModelSelectionByCase.get(release.case_id) !== release.selection_id ||
        mandateStatus?.state !== 'active' ||
        mandateStatus.version !== release.mandate_version ||
        state.policy === undefined ||
        state.policy.policy_version !== release.policy_version ||
        state.policy.policy_content_digest !== release.policy_content_digest ||
        state.policy.evaluator_build_id !== release.evaluator_build_id
      ) {
        fail('stale-output-release', `issued output release ${release.release_id} is not current`);
      }
    }
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
  for (const escalation of state.escalations.values()) {
    const source = state.rulings.get(escalation.ruling_id);
    if (source === undefined) fail('orphan-state', `escalation ${escalation.escalation_id} has no source ruling`);
    if (escalation.successor_ruling_id !== null) {
      if (
        state.rulings.get(escalation.successor_ruling_id) === undefined ||
        source.successor_ruling_id !== escalation.successor_ruling_id
      ) {
        fail('orphan-state', `escalation ${escalation.escalation_id} has an inconsistent successor link`);
      }
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
    const selection = state.modelSelections.get(ruling.binding.selection_id);
    if (
      selection === undefined ||
      state.currentModelSelectionByCase.get(selection.case_id) !== selection.selection_id
    ) {
      fail('stale-issued-ruling', `issued ruling ${ruling.ruling_id} is bound to a stale selection`);
    }
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
