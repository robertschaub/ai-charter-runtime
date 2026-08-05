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
  accessEntry,
  commitToken,
  DIALOGUE_DISPOSITIONS,
  effectIntent,
  evidenceRef,
  GENERAL_DISPOSITIONS,
  type CommitToken,
  hexDigest,
  id,
  mandate,
  registryRecordRef,
  role,
  screeningSignal,
  storeItem,
  timestamp,
  worldId,
  type CommitmentRecord,
  type ConversationStoreEntry,
  type CredentialLabel,
  type CounterName,
  type EvidenceRef,
  type EffectIntent,
  type Disposition,
  type FrozenProposal,
  type Gate,
  type GateRuling,
  type InterventionContract,
  type Mandate,
  type ModelCallAccessEvidence,
  type ModelSelectionAccessEvidence,
  type PatternEvent,
  type RecordEntry,
  type ScreeningSignal,
  type StoreItem,
  type SystemUseDecisionReference,
  type WalOp,
} from './schemas/index.js';
import { applyWorldTransaction, counterValue, mandateVersionKey, type WorldState } from './state.js';
import type { LoadedPolicy } from './policyLoader.js';
import { WalStore, type TransactionActor, type TransactionBuild } from './walStore.js';
import {
  SystemUseDecisionError,
  SystemUseDecisionService,
} from './systemUseDecision.js';

const ZERO_DIGEST = '0'.repeat(64);

export class AuthorizationError extends Error {
  constructor(
    readonly code:
      | 'invalid-mandate-mac'
      | 'proposal-hash'
      | 'proposal-conflict'
      | 'proposal-already-committed'
      | 'policy-not-active'
      | 'system-use-unavailable'
      | 'invalid-counter-delta'
      | 'dialogue-case-scope'
      | 'unauthorized-actor'
      | 'unsupported-ordering-rule',
    message: string,
  ) {
    super(message);
    this.name = 'AuthorizationError';
  }
}

export interface IdFactory {
  next(prefix: 'rul' | 'nce' | 'rsv' | 'esc' | 'pat' | 'rec' | 'acc' | 'rev' | 'cmt' | 'eff' | 'sel' | 'itm'): string;
}

const defaultIds: IdFactory = {
  next: (prefix) => `${prefix}_${randomUUID()}`,
};

export interface AuthorizationCoreOptions {
  readonly store: WalStore;
  readonly keyring: Keyring;
  readonly policy: LoadedPolicy;
  readonly systemUse: SystemUseDecisionService;
  readonly rulingTtlMs?: number;
  readonly commitTokenTtlMs?: number;
  readonly ids?: IdFactory;
  /** Server-owned credential mapping; never take the agent id from the model request body. */
  readonly resolveAuthorizedAgent: (actor: TransactionActor) => string | undefined;
  /** Server-owned signed-card lookup; the orchestrator cannot attest its own model. */
  readonly resolveModelEvidence: (proposal: FrozenProposal) => ModelEvidence;
  /** Server-owned screening over the frozen hash; callers cannot claim that screening occurred. */
  readonly resolveScreening: (
    proposal: FrozenProposal,
    gate: 'submit' | 'verify',
    caseId?: string,
  ) => ScreeningResolution | Promise<ScreeningResolution>;
  /** Recompute local projection/card/fixture evidence while the world lock is held. */
  readonly validateScreeningResolution: (
    resolution: ScreeningResolution,
    proposal: FrozenProposal,
    gate: 'submit' | 'verify',
    caseId?: string,
  ) => boolean;
  /** Server-to-server evidence lookup; a failure or mismatch is an unresolved citation. */
  readonly resolveRegistryEvidence?: (
    citation: RegistryEvidenceCitation,
  ) => RegistryEvidence | null | Promise<RegistryEvidence | null>;
}

export interface RegistryEvidenceCitation {
  readonly kind: 'registry_record';
  readonly id: string;
  readonly retrieved_at: string;
}

export type RegistryEvidence = Extract<EvidenceRef, { readonly kind: 'registry_record' }>;

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
  /** Protocol scope for dialogue escalations; never derived from model output. */
  readonly caseId?: string;
  /** Authorization-service classifications only; endpoint code must not pass model-authored labels through. */
  readonly context?: Readonly<Record<string, unknown>>;
}

interface PreparedRuleProposalInput extends RuleProposalInput {
  readonly signals: readonly ScreeningSignal[];
  readonly screeningPerformed: boolean;
  readonly screeningEvidenceRefs: readonly EvidenceRef[];
}

export interface ScreeningResolution {
  readonly performed: boolean;
  readonly signals: readonly ScreeningSignal[];
  readonly evidenceRefs: readonly EvidenceRef[];
}

export interface RuleProposalResult {
  readonly ruling: GateRuling;
  readonly escalationId: string | null;
  readonly recordEntryId: string;
  readonly mandateNarrowed: boolean;
}

export interface DisposeEscalationInput {
  readonly escalationId: string;
  readonly disposition: Disposition;
  readonly actor: TransactionActor;
}

export type DisposeEscalationResult =
  | {
      readonly accepted: true;
      readonly status: 'disposed';
      readonly successor: RuleProposalResult | null;
      readonly recordEntryId: string;
      readonly reviewObligationId: string | null;
    }
  | {
      readonly accepted: false;
      readonly defect:
        | 'missing-escalation'
        | 'wrong-role'
        | 'disposition-not-permitted'
        | 'late-disposition';
      readonly terminalState?: 'disposed' | 'timed_out' | 'cancelled';
      readonly recordEntryId: string | null;
    };

export interface RespondDialogueInput {
  readonly escalationId: string;
  readonly disposition: Disposition;
  readonly actor: TransactionActor;
  readonly answerText?: string;
  readonly evidenceRef?: RegistryEvidenceCitation;
  readonly scope?: Readonly<{ readonly item_ref: string; readonly applies_to: 'this_case_only' }>;
}

export interface PutConversationItemsInput {
  readonly caseId: string;
  readonly items: readonly StoreItem[];
  readonly actor: TransactionActor;
}

export type RespondDialogueResult =
  | {
      readonly accepted: true;
      readonly status: 'disposed';
      readonly recordEntryId: string;
      readonly reviewObligationId: string | null;
    }
  | {
      readonly accepted: false;
      readonly defect:
        | 'missing-escalation'
        | 'wrong-role'
        | 'disposition-not-permitted'
        | 'evidence-required'
        | 'invalid-response'
        | 'late-response';
      readonly terminalState?: 'disposed' | 'timed_out' | 'cancelled';
      readonly recordEntryId: string | null;
    };

export interface SubmitChallengeInput {
  readonly actionId: string;
  readonly contestedEntryId: string;
  readonly correctionText: string;
  readonly actor: TransactionActor;
}

export type SubmitChallengeResult =
  | {
      readonly accepted: true;
      readonly status: 'opened';
      readonly recordEntryId: string;
      readonly reviewObligationId: string;
    }
  | {
      readonly accepted: false;
      readonly defect:
        | 'wrong-role'
        | 'invalid-correction'
        | 'missing-action'
        | 'missing-entry'
        | 'entry-not-in-action'
        | 'already-open';
      readonly recordEntryId: null;
      readonly reviewObligationId?: string;
    };

export interface ContinueEscalationRevisionInput {
  readonly escalationId: string;
  readonly proposal: FrozenProposal;
  readonly actor: TransactionActor;
  readonly context?: Readonly<Record<string, unknown>>;
}

export type ContinueEscalationRevisionResult =
  | {
      readonly accepted: true;
      readonly stages: readonly RuleProposalResult[];
      readonly successor: RuleProposalResult;
    }
  | {
      readonly accepted: false;
      readonly defect:
        | 'missing-escalation'
        | 'wrong-state'
        | 'revision-not-permitted'
        | 'already-continued';
      readonly recordEntryId: string | null;
    };

export interface RecordAccessInput {
  readonly route: string;
  readonly authenticatedActor: CredentialLabel | null;
  readonly claimedActor: { readonly role: 'principal' | 'case_officer' | 'applicant' | null; readonly session?: string } | null;
  readonly outcome: 'served' | 'unauthenticated' | 'forbidden' | 'rate-limited';
  readonly httpStatus: number;
  readonly recorder: TransactionActor;
  readonly readLengths?: Readonly<Record<string, number>>;
  readonly operationEvidence?: ModelCallAccessEvidence | ModelSelectionAccessEvidence;
  readonly suppressedCount?: number;
  readonly suppressionWindowMs?: number;
  readonly suppressionFinal?: boolean;
}

export type CommitDefect =
  | AuthorityDefect
  | 'not-allowed'
  | 'counter-invalid'
  | 'expired-ruling'
  | 'system-use-unavailable'
  | 'unauthorized-caller';

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
  readonly servicesLedgerId: string;
  readonly actor: TransactionActor;
}

export interface EffectOutcomeReportInput {
  readonly worldId: string;
  readonly commitmentId: string;
  readonly effectId: string;
  readonly idempotencyKey: string;
  readonly effectRequestDigest: string;
  readonly servicesHostBootId: string;
  readonly servicesLedgerId: string;
  readonly outcome: 'success' | 'failed';
  readonly recordedAt: string;
  readonly detail?: string;
  readonly delivery: 'executed' | 'retry' | 'reconciliation-probe';
  readonly actor: TransactionActor;
}

export type EffectOutcomeReportResult =
  | {
      readonly accepted: true;
      readonly status: 'recorded' | 'already-recorded' | 'retry-recorded';
      readonly recordEntryId: string | null;
    }
  | {
      readonly accepted: false;
      readonly defect:
        | 'unauthorized-reporter'
        | 'missing-commitment'
        | 'binding-mismatch'
        | 'conflicting-outcome'
        | 'terminal-commitment';
    };

export type MarkUnknownResult =
  | { readonly ok: true; readonly status: 'opened' | 'already-open'; readonly escalationId: string }
  | { readonly ok: false; readonly defect: 'unauthorized-reporter' | 'missing-commitment' | 'terminal-commitment' };

export type ReconcileAbsentResult =
  | { readonly ok: true; readonly status: 'reconciled' | 'already-reconciled'; readonly recordEntryId: string | null }
  | {
      readonly ok: false;
      readonly defect:
        | 'unauthorized-reporter'
        | 'missing-commitment'
        | 'host-still-running'
        | 'ledger-continuity-mismatch'
        | 'effect-already-recorded'
        | 'terminal-commitment';
    };

export type CommitmentProbe =
  | {
      readonly state: 'recorded';
      readonly boot_id: string;
      readonly record: {
        readonly world_id: string;
        readonly services_host_boot_id: string;
        readonly services_ledger_id: string;
        readonly effect_id: string;
        readonly idempotency_key: string;
        readonly effect_request_digest: string;
        readonly outcome: 'success' | 'failed';
        readonly recorded_at: string;
        readonly detail?: string;
      };
    }
  | { readonly state: 'absent'; readonly boot_id: string; readonly ledger_id: string };

export interface ReconcileCommitmentOptions {
  readonly commitmentId: string;
  readonly probe: (idempotencyKey: string) => Promise<CommitmentProbe>;
  readonly attempts?: number;
  readonly backoffMs?: readonly number[];
  readonly delay?: (milliseconds: number) => Promise<void>;
}

export type ReconcileCommitmentResult =
  | { readonly resolution: 'recorded'; readonly report: EffectOutcomeReportResult }
  | { readonly resolution: 'absent-after-restart'; readonly result: ReconcileAbsentResult }
  | { readonly resolution: 'unknown'; readonly result: MarkUnknownResult }
  | { readonly resolution: 'already-terminal' };

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
  const selection = state.modelSelections.get(input.proposal.selection_id);
  if (
    selection === undefined ||
    state.currentModelSelectionByCase.get(selection.case_id) !== selection.selection_id ||
    (input.caseId !== undefined && selection.case_id !== input.caseId) ||
    selection.mandate_id !== input.proposal.mandate_ref.mandate_id ||
    selection.mandate_version !== input.proposal.mandate_ref.version ||
    selection.target.card_id !== input.proposal.acting_model.card_id ||
    selection.target.card_version !== input.proposal.acting_model.card_version ||
    selection.target.requested_id !== input.proposal.acting_model.requested_id ||
    selection.target.card_digest !== approved?.card_digest ||
    (modelEvidence.cardStatus === 'current' &&
      (selection.target.card_digest !== modelEvidence.cardDigest ||
        selection.target.verifying_key_id !== modelEvidence.cardKeyId))
  ) {
    defects.push('stale-selection');
  }
  if (approved === undefined || !modelEvidence.servedModelAccepted) defects.push('substituted-model');
  if (
    modelEvidence.cardStatus === 'withdrawn' ||
    (modelEvidence.cardStatus === 'current' && approved !== undefined && approved.card_digest !== modelEvidence.cardDigest)
  ) {
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

function rulingReservationsMatchDeltas(
  ruling: GateRuling,
  deltas: Partial<Record<CounterName, number>>,
): boolean {
  const expected = new Map(
    (Object.entries(deltas) as [CounterName, number][]).filter(([, delta]) => delta !== 0),
  );
  if (ruling.counter_reservations.length !== expected.size) return false;
  const seen = new Set<CounterName>();
  for (const reservation of ruling.counter_reservations) {
    if (seen.has(reservation.counter) || expected.get(reservation.counter) !== reservation.delta) return false;
    seen.add(reservation.counter);
  }
  return seen.size === expected.size;
}

function requireMandateActor(actor: TransactionActor, allowBootstrap: boolean): void {
  if (actor.credential === 'role:principal') return;
  if (allowBootstrap && actor.credential === 'proc:authz') return;
  throw new AuthorizationError('unauthorized-actor', 'only the principal may change mandate authority');
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

function proposalRevisionInvalidations(state: WorldState, proposal: FrozenProposal): WalOp[] {
  return invalidationOps(
    state,
    (candidate) => {
      if (candidate.binding.frozen_proposal_hash === proposal.proposal_hash) return false;
      const priorId = state.proposalByHash.get(candidate.binding.frozen_proposal_hash);
      const prior = priorId === undefined ? undefined : state.proposals.get(priorId);
      return prior?.action_id === proposal.action_id;
    },
    'proposal-revision',
  );
}

function authorityChainIds(mandateValue: Mandate | undefined): string[] {
  if (mandateValue === undefined) return [];
  return unique(mandateValue.authority_chain.flatMap((hop) => [hop.delegator, hop.delegate]));
}

function rulingRecord(
  state: WorldState,
  systemUse: SystemUseDecisionService,
  input: RuleProposalInput,
  ruling: GateRuling,
  mandateValue: Mandate | undefined,
  entryId: string,
  at: string,
  intervention: { escalationId: string; contract: InterventionContract } | null,
  recordActor: TransactionActor = input.actor,
  extraBasis: readonly string[] = [],
): RecordEntry {
  const dialogue =
    intervention !== null &&
    intervention.contract.permitted_dispositions.every((value) =>
      (DIALOGUE_DISPOSITIONS as readonly string[]).includes(value),
    );
  return {
    world_id: input.proposal.world_id,
    entry_id: entryId,
    at,
    authenticated_actor: recordActor.credential,
    claimed_actor: { role: recordActor.claimed_role },
    system_use_decision: ruling.binding.system_use_decision,
    system_use_current_at_record: systemUse.isReferenceCurrent(state, ruling.binding.system_use_decision, at),
    proposed_action: input.proposal.proposed_action,
    basis: [
      ...input.proposal.material_inputs.map((item) => item.id),
      ...input.proposal.derived_claims.map((item) => item.id),
      ...extraBasis,
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
            payload: dialogue
              ? {
                  kind: 'dialogue_trigger_raised',
                  contract: intervention.contract,
                  standing_class: intervention.contract.decision_and_route.standing_class,
                  question_text: ruling.reason,
                }
              : { kind: 'escalation_raised', contract: intervention.contract, reason: ruling.reason },
          },
    challenge_and_remedy: null,
  };
}

function escalationEventRecord(
  state: WorldState,
  systemUse: SystemUseDecisionService,
  ruling: GateRuling,
  actor: TransactionActor,
  entryId: string,
  at: string,
  event: RecordEntry['human_intervention_event'],
  challengeRoute: string | null = null,
): RecordEntry {
  const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
  if (proposal === undefined) throw new Error(`ruling ${ruling.ruling_id} lost its proposal`);
  const mandateValue = state.mandates.get(
    mandateVersionKey(ruling.binding.mandate_id, ruling.binding.mandate_version),
  );
  return {
    world_id: state.worldId,
    entry_id: entryId,
    at,
    authenticated_actor: actor.credential,
    claimed_actor: { role: actor.claimed_role },
    system_use_decision: ruling.binding.system_use_decision,
    system_use_current_at_record: systemUse.isReferenceCurrent(state, ruling.binding.system_use_decision, at),
    proposed_action: proposal.proposed_action,
    basis: [...proposal.material_inputs.map((item) => item.id), ...proposal.derived_claims.map((item) => item.id)],
    authority_chain: authorityChainIds(mandateValue),
    admissibility_decision: { ruling_id: ruling.ruling_id, verdict: ruling.verdict },
    policy_model_version: {
      policy_version: ruling.policy_version,
      policy_content_digest: ruling.policy_content_digest,
      evaluator_build_id: ruling.evaluator_build_id,
      acting_model_requested_id: proposal.acting_model.requested_id,
      acting_model_served_id: proposal.acting_model.served_id,
    },
    commitment_and_effect: null,
    human_intervention_event: event,
    challenge_and_remedy:
      challengeRoute === null ? null : { route: challengeRoute, opened_at: at },
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

function committedSystemUseReference(ruling: GateRuling): SystemUseDecisionReference {
  if (ruling.binding.system_use_decision === null) {
    throw new AuthorizationError('system-use-unavailable', 'an authority-bearing ruling lost its system-use decision');
  }
  return ruling.binding.system_use_decision;
}

function commitmentRecordEntry(
  state: WorldState,
  systemUse: SystemUseDecisionService,
  ruling: GateRuling,
  actor: TransactionActor,
  entryId: string,
  commitmentId: string,
  effectId: string,
  idempotencyKey: string,
  effectRequestDigest: string,
  servicesLedgerId: string,
  boundAt: string,
  tokenExpiresAt: string,
): RecordEntry {
  const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
  if (proposal === undefined) throw new Error(`ruling ${ruling.ruling_id} lost its proposal`);
  const mandateValue = state.mandates.get(mandateVersionKey(ruling.binding.mandate_id, ruling.binding.mandate_version));
  const systemUseDecision = committedSystemUseReference(ruling);
  if (!systemUse.isReferenceCurrent(state, systemUseDecision, boundAt)) {
    throw new AuthorizationError('system-use-unavailable', 'commitment record cannot bind a stale system-use decision');
  }
  return {
    world_id: state.worldId,
    entry_id: entryId,
    at: boundAt,
    authenticated_actor: actor.credential,
    claimed_actor: { role: actor.claimed_role },
    system_use_decision: systemUseDecision,
    system_use_current_at_record: true,
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
      services_ledger_id: servicesLedgerId,
      system_use_decision: systemUseDecision,
      system_use_current_at_record: true,
      service: ruling.binding.service,
      bound_at: boundAt,
      token_expires_at: tokenExpiresAt,
    },
    human_intervention_event: null,
    challenge_and_remedy: null,
  };
}

function commitmentEventRecordEntry(
  state: WorldState,
  systemUse: SystemUseDecisionService,
  commitment: CommitmentRecord,
  actor: TransactionActor,
  entryId: string,
  at: string,
  event: NonNullable<RecordEntry['commitment_and_effect']>,
  intervention: RecordEntry['human_intervention_event'] = null,
): RecordEntry {
  const ruling = state.rulings.get(commitment.ruling_id);
  if (ruling === undefined) throw new Error(`commitment ${commitment.commitment_id} lost its ruling`);
  const proposalId = state.proposalByHash.get(commitment.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
  if (proposal === undefined) throw new Error(`commitment ${commitment.commitment_id} lost its proposal`);
  const mandateValue = state.mandates.get(
    mandateVersionKey(ruling.binding.mandate_id, ruling.binding.mandate_version),
  );
  const systemUseCurrent = systemUse.isReferenceCurrent(state, commitment.system_use_decision, at);
  const boundedEvent =
    event.event === 'effect_outcome'
      ? { ...event, system_use_current_at_record: systemUseCurrent }
      : event;
  return {
    world_id: state.worldId,
    entry_id: entryId,
    at,
    authenticated_actor: actor.credential,
    claimed_actor: { role: actor.claimed_role },
    system_use_decision: commitment.system_use_decision,
    system_use_current_at_record: systemUseCurrent,
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
    commitment_and_effect: boundedEvent,
    human_intervention_event: intervention,
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
  readonly #resolveScreening: AuthorizationCoreOptions['resolveScreening'];
  readonly #validateScreeningResolution: AuthorizationCoreOptions['validateScreeningResolution'];
  readonly #resolveRegistryEvidence: NonNullable<AuthorizationCoreOptions['resolveRegistryEvidence']>;
  readonly #systemUse: SystemUseDecisionService;

  constructor(options: AuthorizationCoreOptions) {
    this.#store = options.store;
    this.#keyring = options.keyring;
    this.#policy = options.policy;
    this.#systemUse = options.systemUse;
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
    this.#resolveScreening = options.resolveScreening;
    this.#validateScreeningResolution = options.validateScreeningResolution;
    this.#resolveRegistryEvidence = options.resolveRegistryEvidence ?? (() => null);
  }

  async #screeningEvidence(
    proposal: FrozenProposal,
    gate: Gate,
    caseId?: string,
  ): Promise<ScreeningResolution> {
    if (gate !== 'submit' && gate !== 'verify') return { signals: [], performed: false, evidenceRefs: [] };
    try {
      const resolved = await this.#resolveScreening(proposal, gate, caseId);
      return {
        signals: resolved.signals.map((signal) => screeningSignal.parse(signal)),
        performed: resolved.performed,
        evidenceRefs: resolved.evidenceRefs.map((reference) => evidenceRef.parse(reference)),
      };
    } catch {
      return {
        signals: [],
        performed: false,
        evidenceRefs: [
          evidenceRef.parse({
            kind: 'screening_skipped',
            provider: null,
            role: 'screening',
            reason: 'resolver-error',
            suspect_item_ids: [],
          }),
        ],
      };
    }
  }

  #validatedScreening(input: PreparedRuleProposalInput): ScreeningResolution {
    if (input.gate !== 'submit' && input.gate !== 'verify') {
      return { signals: [], performed: false, evidenceRefs: [] };
    }
    const candidate = {
      signals: input.signals,
      performed: input.screeningPerformed,
      evidenceRefs: input.screeningEvidenceRefs,
    };
    try {
      if (this.#validateScreeningResolution(candidate, input.proposal, input.gate, input.caseId)) return candidate;
    } catch {}
    return {
      signals: [],
      performed: false,
      evidenceRefs: [
        evidenceRef.parse({
          kind: 'screening_skipped',
          provider: null,
          role: 'screening',
          reason: 'resolver-error',
          suspect_item_ids: [],
        }),
      ],
    };
  }

  #resolveModelEvidenceFailClosed(proposal: FrozenProposal): ModelEvidence {
    try {
      return this.#resolveModelEvidence(proposal);
    } catch {
      // Startup validation still throws while constructing CardRegistry. Once the
      // service is running, a malformed or transient card set is ambiguity, not
      // authority: convert it to the existing recorded stale-card path.
      return {
        servedModelAccepted: false,
        cardStatus: 'withdrawn',
        cardKeyId: 'unverified',
        cardDigest: ZERO_DIGEST,
      };
    }
  }

  async activatePolicy(actor: TransactionActor = { credential: 'proc:authz', claimed_role: null }): Promise<void> {
    if (actor.credential !== 'proc:authz') {
      throw new AuthorizationError('unauthorized-actor', 'only the authorization process may activate policy');
    }
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
    if (actor.credential !== 'proc:authz') {
      throw new AuthorizationError('unauthorized-actor', 'only the authorization process may reload policy');
    }
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
    requireMandateActor(actor, true);
    const parsed = mandate.parse(value);
    requireValidMandateMac(this.#keyring, parsed);
    await this.#store.transactWithState('mandate_grant', actor, (state, at) => {
      try {
        const prepared = this.#systemUse.prepareForMandate(state, parsed, this.#policy.policy.policy_version, at);
        return { ops: [...prepared.ops, { op: 'mandate.grant' as const, mandate: parsed }], result: undefined };
      } catch (error) {
        if (error instanceof SystemUseDecisionError) {
          throw new AuthorizationError('system-use-unavailable', 'current system-use decision is unavailable');
        }
        throw error;
      }
    });
  }

  /**
   * M5.1 startup/ingestion seam. Only the authorization process may attach classified
   * items to a case; no HTTP route exposes this method to the orchestrator or browser.
   */
  async putConversationItems(input: PutConversationItemsInput): Promise<void> {
    if (input.actor.credential !== 'proc:authz') {
      throw new AuthorizationError('unauthorized-actor', 'only authorization may persist conversation items');
    }
    const caseId = id.parse(input.caseId);
    const entries: ConversationStoreEntry[] = input.items.map((item) => ({
      world_id: this.#store.snapshot().worldId,
      case_id: caseId,
      item: storeItem.parse(item),
    }));
    if (entries.length === 0) return;
    await this.#store.transactWithState('conversation_items_put', input.actor, (state) => {
      const ops: WalOp[] = [];
      for (const entry of entries) {
        const current = state.storeItems.get(entry.item.id);
        if (current === undefined) ops.push({ op: 'store.put', entry });
        else if (canonicalize(current) !== canonicalize(entry)) {
          throw new AuthorizationError(
            'proposal-conflict',
            `conversation item ${entry.item.id} is already bound to different content or scope`,
          );
        }
      }
      return { ops, result: undefined };
    });
  }

  async amendMandate(value: Mandate, actor: TransactionActor): Promise<void> {
    requireMandateActor(actor, false);
    const parsed = mandate.parse(value);
    requireValidMandateMac(this.#keyring, parsed);
    await this.#store.transactWithState('mandate_amend', actor, (state, at) => {
      try {
        this.#systemUse.resolve(state, parsed, this.#policy.policy.policy_version, at);
      } catch (error) {
        if (error instanceof SystemUseDecisionError) {
          throw new AuthorizationError('system-use-unavailable', 'current system-use decision is unavailable');
        }
        throw error;
      }
      return { ops: [
        ...invalidationOps(
          state,
          (ruling) => ruling.binding.mandate_id === parsed.mandate_id,
          'mandate-amendment',
        ),
        { op: 'mandate.amend', mandate: parsed },
      ],
      result: undefined };
    });
  }

  async revokeMandate(mandateId: string, version: number, actor: TransactionActor): Promise<void> {
    requireMandateActor(actor, false);
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
    if (input.actor.credential !== 'proc:orchestrator') {
      throw new AuthorizationError('unauthorized-actor', 'only the orchestrator may submit a proposal for ruling');
    }
    const proposal = frozenProposal.parse(input.proposal);
    verifyProposalHash(proposal);
    const screening = await this.#screeningEvidence(proposal, input.gate, input.caseId);
    const completed = await this.#store.transactWithState('ruling_issue', input.actor, (state, at) =>
      this.#buildRuling(
        {
          ...input,
          proposal,
          signals: screening.signals,
          screeningPerformed: screening.performed,
          screeningEvidenceRefs: screening.evidenceRefs,
        },
        state,
        at,
      ),
    );
    return completed.result;
  }

  #buildRuling(
    input: PreparedRuleProposalInput,
    state: WorldState,
    at: string,
    options: {
      readonly recordActor?: TransactionActor;
      readonly extraBasis?: readonly string[];
      readonly authorizedAgentId?: string;
    } = {},
  ): TransactionBuild<RuleProposalResult> {
    const proposal = input.proposal;
    const policy = this.#policy;
    const screening = this.#validatedScreening(input);
      const existing = state.proposals.get(proposal.proposal_id);
      if (existing !== undefined && existing.proposal_hash !== proposal.proposal_hash) {
        throw new AuthorizationError('proposal-conflict', `proposal id ${proposal.proposal_id} is already frozen`);
      }
      const matchingRulings = [...state.rulings.values()].filter(
        (candidate) =>
          candidate.gate === input.gate &&
          candidate.binding.frozen_proposal_hash === proposal.proposal_hash &&
          candidate.binding.service === input.service &&
          candidate.binding.action_class === input.actionClass,
      );
      const priorRuling = matchingRulings.find((candidate) => candidate.status === 'issued');
      if (priorRuling?.status === 'issued') {
        const priorRecord = state.actionRecords.find(
          (entry) => entry.admissibility_decision.ruling_id === priorRuling.ruling_id,
        );
        if (priorRecord === undefined) throw new Error(`ruling ${priorRuling.ruling_id} lost its action record`);
        const priorEscalation = [...state.escalations.values()].find(
          (entry) => entry.ruling_id === priorRuling.ruling_id && entry.source_commitment_id === null,
        );
        return {
          ops: [],
          result: {
            ruling: priorRuling,
            escalationId: priorEscalation?.escalation_id ?? null,
            recordEntryId: priorRecord.entry_id,
            mandateNarrowed: false,
          },
        };
      }
      if (matchingRulings.some((candidate) => candidate.status === 'consumed')) {
        throw new AuthorizationError(
          'proposal-already-committed',
          `proposal ${proposal.proposal_id} already has a committed ${input.gate} ruling`,
        );
      }
      const revisionInvalidations = proposalRevisionInvalidations(state, proposal);
      // Evaluate ceilings after releasing the superseded revision's in-flight reservations.
      // This mutates only WalStore's disposable build snapshot; the returned ops remain the
      // sole durable mutation path and are replayed again against the real preview state.
      if (revisionInvalidations.length > 0) applyWorldTransaction(state, revisionInvalidations, at);
      const defects = authorityDefects(
        state,
        { ...input, proposal },
        policy,
        this.#keyring,
        at,
        options.authorizedAgentId ?? this.#resolveAuthorizedAgent(input.actor),
        this.#resolveModelEvidenceFailClosed(proposal),
      );
      if (defects.defects.includes('stale-policy')) {
        throw new AuthorizationError('policy-not-active', 'the configured policy is not the active durable policy');
      }
      const systemUseMandate =
        defects.mandate ??
        state.mandates.get(
          mandateVersionKey(
            proposal.mandate_ref.mandate_id,
            state.mandateStatus.get(proposal.mandate_ref.mandate_id)?.version ?? proposal.mandate_ref.version,
          ),
        );
      let systemUseDecision: SystemUseDecisionReference | null = null;
      if (systemUseMandate !== undefined) {
        try {
          systemUseDecision = this.#systemUse.resolve(state, systemUseMandate, policy.policy.policy_version, at);
        } catch (error) {
          if (error instanceof SystemUseDecisionError) {
            throw new AuthorizationError('system-use-unavailable', 'current system-use decision is unavailable');
          }
          throw error;
        }
      }
      const currentSelection = state.modelSelections.get(proposal.selection_id);
      if (
        systemUseDecision !== null &&
        (currentSelection === undefined ||
          canonicalize(currentSelection.system_use_decision) !== canonicalize(systemUseDecision)) &&
        !defects.defects.includes('stale-selection')
      ) {
        defects.defects.push('stale-selection');
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
      const policyEvaluation = evaluatePolicy(policy.policy, {
        gate: input.gate,
        proposal,
        mandate: defects.mandate,
        context: input.context ?? {},
        counters,
        signals: screening.signals,
        screeningPerformed: screening.performed,
        patternEvents: state.patternEvents,
        now: at,
        authorityDefects: defects.defects,
        reauthorizationRequired: defects.reauthorizationRequired,
      });

      const wouldExceed = Object.values(counters).some(
        (counter) => counter.limit !== null && counter.current + counter.delta > counter.limit,
      );
      const evaluation =
        wouldExceed && policyEvaluation.verdict === 'allow'
          ? {
              verdict: 'escalate' as const,
              uxClass: 'stop' as const,
              matchedRuleId: 'default:aggregate-ceiling',
              reason: 'The proposal would cross a cumulative mandate ceiling.',
              interventionContract: policy.policy.aggregate_ceiling_contract,
            }
          : policyEvaluation;
      if (systemUseDecision === null && evaluation.verdict !== 'deny') {
        throw new AuthorizationError('system-use-unavailable', 'current system-use decision is unavailable');
      }

      const rulingId = this.#ids.next('rul');
      const nonceId = this.#ids.next('nce');
      const mandateExpiry = defects.mandate?.expires_at;
      const mandateWindowEnd = defects.mandate?.limits.time_window.not_after;
      const ttlEnd = addMilliseconds(at, this.#rulingTtlMs);
      const notAfter =
        evaluation.verdict === 'deny'
          ? ttlEnd
          : [ttlEnd, mandateExpiry, mandateWindowEnd].filter((value): value is string => value !== undefined).sort()[0] ?? ttlEnd;
      // Only a Commit allow can bind capacity. Pre-commit gates are evidence, not commitments.
      const reserve = input.gate === 'commit' && evaluation.verdict !== 'deny' && !wouldExceed;
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
          selection_id: proposal.selection_id,
          card_digest: defects.cardDigest,
          card_key_id: defects.cardKeyId,
          system_use_decision: systemUseDecision,
          service: input.service,
          action_class: input.actionClass,
          nonce: nonceId,
          validity_window: { not_before: at, not_after: notAfter },
        },
        ux_class: evaluation.uxClass,
        reason: evaluation.reason,
        evidence_refs: [...screening.evidenceRefs, ...screening.signals],
        counter_reservations: reservations,
        issued_at: at,
        status: 'issued',
        successor_ruling_id: null,
      });
      const escalationId = evaluation.verdict === 'escalate' ? this.#ids.next('esc') : null;
      const recordEntryId = this.#ids.next('rec');
      const ops: WalOp[] = [...revisionInvalidations];
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
        const dialogueContract = contract.permitted_dispositions.every((value) =>
          (DIALOGUE_DISPOSITIONS as readonly string[]).includes(value),
        );
        if (dialogueContract && input.caseId === undefined) {
          throw new AuthorizationError(
            'dialogue-case-scope',
            'a dialogue escalation must be bound to a server-validated case id',
          );
        }
        const escalationExpires = addMilliseconds(at, contract.response_bound_and_default.response_bound_ms);
        ops.push({
          op: 'escalation.open',
          escalation: {
            world_id: proposal.world_id,
            escalation_id: escalationId,
            case_id: dialogueContract ? (input.caseId ?? null) : null,
            ruling_id: rulingId,
            source_commitment_id: null,
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
        state,
        this.#systemUse,
        { ...input, proposal },
        ruling,
        defects.mandate,
        recordEntryId,
        at,
        escalationId === null || contract === null ? null : { escalationId, contract },
        options.recordActor,
        options.extraBasis,
      );
      ops.push({ op: 'record.action.append', entry });
      return { ops, result: { ruling, escalationId, recordEntryId, mandateNarrowed } };
  }

  #patternNarrowingOps(
    state: WorldState,
    pattern: PatternEvent,
    at: string,
    excludeRulingId: string,
  ): WalOp[] {
    const status = state.mandateStatus.get(pattern.mandate_id);
    const current =
      status === undefined ? undefined : state.mandates.get(mandateVersionKey(pattern.mandate_id, status.version));
    if (
      current === undefined ||
      current.state !== 'active' ||
      !escalationPatternRequiresNarrowing(
        this.#policy.policy,
        [...state.patternEvents, pattern],
        pattern.mandate_id,
        at,
      )
    ) {
      return [];
    }
    return [
      ...invalidationOps(
        state,
        (candidate) =>
          candidate.ruling_id !== excludeRulingId && candidate.binding.mandate_id === pattern.mandate_id,
        'escalation-pattern-narrowing',
      ),
      {
        op: 'mandate.amend',
        mandate: bindMandate(this.#keyring, {
          ...mandateBody(current),
          version: current.version + 1,
          state: 'suspended',
          issued_at: at,
        }),
      },
    ];
  }

  async disposeEscalation(input: DisposeEscalationInput): Promise<DisposeEscalationResult> {
    const escalationId = id.parse(input.escalationId);
    const disposition = input.disposition;
    let allowScreening: ScreeningResolution = {
      signals: [],
      performed: false,
      evidenceRefs: [],
    };
    if (disposition === 'allow-within-scope') {
      const snapshot = this.#store.snapshot();
      const escalation = snapshot.escalations.get(escalationId);
      const ruling = escalation === undefined ? undefined : snapshot.rulings.get(escalation.ruling_id);
      const proposalId =
        escalation === undefined ? undefined : snapshot.proposalByHash.get(escalation.frozen_proposal_hash);
      const proposal = proposalId === undefined ? undefined : snapshot.proposals.get(proposalId);
      const actorRole = input.actor.credential.startsWith('role:')
        ? role.parse(input.actor.credential.slice('role:'.length))
        : null;
      const eligibleRoles =
        escalation === undefined
          ? []
          : [
              escalation.contract.decision_and_route.eligible_role,
              ...escalation.contract.decision_and_route.substitute_roles,
            ];
      if (
        escalation?.state === 'open' &&
        escalation.contract.permitted_dispositions.includes(disposition) &&
        actorRole !== null &&
        eligibleRoles.includes(actorRole) &&
        ruling !== undefined &&
        proposal !== undefined
      ) {
        allowScreening = await this.#screeningEvidence(
          proposal,
          ruling.gate,
          escalation.case_id === null ? undefined : escalation.case_id,
        );
      }
    }

    const completed = await this.#store.transactWithState<DisposeEscalationResult>(
      'escalation_dispose',
      input.actor,
      (state, at) => {
        const escalation = state.escalations.get(escalationId);
        if (escalation === undefined) {
          return { ops: [], result: { accepted: false, defect: 'missing-escalation', recordEntryId: null } };
        }
        const ruling = state.rulings.get(escalation.ruling_id);
        if (ruling === undefined) throw new Error(`escalation ${escalationId} lost its ruling`);

        const lateRecord = (terminalState: 'disposed' | 'timed_out' | 'cancelled'): TransactionBuild<DisposeEscalationResult> => {
          const recordEntryId = this.#ids.next('rec');
          return {
            ops: [
              {
                op: 'record.action.append',
                entry: escalationEventRecord(
                  state,
                  this.#systemUse,
                  ruling,
                  input.actor,
                  recordEntryId,
                  at,
                  {
                    event: 'late_disposition_ignored',
                    escalation_id: escalationId,
                    attempted_disposition: disposition,
                    authenticated_actor: input.actor.credential,
                    terminal_state: terminalState,
                    at,
                  },
                ),
              },
            ],
            result: {
              accepted: false,
              defect: 'late-disposition',
              terminalState,
              recordEntryId,
            },
          };
        };

        if (escalation.state !== 'open') return lateRecord(escalation.state);

        if (at >= escalation.expires_at) {
          const appliedDefault = escalation.contract.response_bound_and_default.safe_default.disposition;
          const timeoutRecordEntryId = this.#ids.next('rec');
          const lateRecordEntryId = this.#ids.next('rec');
          const ops: WalOp[] = [
            { op: 'escalation.timeout', escalation_id: escalationId, applied_default: appliedDefault },
          ];
          if (ruling.status === 'issued') {
            if (at >= ruling.binding.validity_window.not_after) {
              ops.push({ op: 'ruling.expire', ruling_id: ruling.ruling_id });
              const nonce = state.nonces.get(ruling.binding.nonce);
              if (nonce?.state === 'issued') ops.push({ op: 'nonce.expire', nonce_id: nonce.nonce_id });
            } else {
              ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason: 'escalation-timeout' });
            }
            for (const reservation of ruling.counter_reservations) {
              if (state.reservations.get(reservation.id)?.state === 'reserved') {
                ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason: 'escalation-timeout' });
              }
            }
          }
          const timeoutPattern: PatternEvent = {
            world_id: state.worldId,
            event_id: this.#ids.next('pat'),
            mandate_id: ruling.binding.mandate_id,
            escalation_id: escalationId,
            kind: 'timeout',
            at,
          };
          ops.push({ op: 'pattern.record', event: timeoutPattern });
          ops.push(...this.#patternNarrowingOps(state, timeoutPattern, at, ruling.ruling_id));
          ops.push({
            op: 'record.action.append',
            entry: escalationEventRecord(state, this.#systemUse, ruling, { credential: 'proc:authz', claimed_role: null }, timeoutRecordEntryId, at, {
              event: 'human_intervention_event',
              escalation_id: escalationId,
              payload: { kind: 'escalation_timeout', applied_default: appliedDefault, at },
            }),
          });
          ops.push({
            op: 'record.action.append',
            entry: escalationEventRecord(state, this.#systemUse, ruling, input.actor, lateRecordEntryId, at, {
              event: 'late_disposition_ignored',
              escalation_id: escalationId,
              attempted_disposition: disposition,
              authenticated_actor: input.actor.credential,
              terminal_state: 'timed_out',
              at,
            }),
          });
          return {
            ops,
            result: {
              accepted: false,
              defect: 'late-disposition',
              terminalState: 'timed_out',
              recordEntryId: lateRecordEntryId,
            },
          };
        }

        const refuse = (
          defect: 'wrong-role' | 'disposition-not-permitted',
        ): TransactionBuild<DisposeEscalationResult> => {
          const recordEntryId = this.#ids.next('rec');
          return {
            ops: [
              {
                op: 'record.action.append',
                entry: escalationEventRecord(state, this.#systemUse, ruling, input.actor, recordEntryId, at, {
                  event: 'human_intervention_event',
                  escalation_id: escalationId,
                  payload: {
                    kind: 'disposition_refused',
                    attempted_disposition: disposition,
                    authenticated_actor: input.actor.credential,
                    reason_code: defect === 'wrong-role' ? 'wrong_role' : 'disposition_not_permitted',
                    at,
                  },
                }),
              },
            ],
            result: { accepted: false, defect, recordEntryId },
          };
        };
        const responderRole = input.actor.credential.startsWith('role:')
          ? role.parse(input.actor.credential.slice('role:'.length))
          : null;
        const eligibleRoles = [
          escalation.contract.decision_and_route.eligible_role,
          ...escalation.contract.decision_and_route.substitute_roles,
        ];
        if (responderRole === null || !eligibleRoles.includes(responderRole)) return refuse('wrong-role');
        const generalContract = escalation.contract.permitted_dispositions.every((value) =>
          (GENERAL_DISPOSITIONS as readonly string[]).includes(value),
        );
        if (!generalContract || !(GENERAL_DISPOSITIONS as readonly string[]).includes(disposition)) {
          return refuse('disposition-not-permitted');
        }
        if (!escalation.contract.permitted_dispositions.includes(disposition)) {
          return refuse('disposition-not-permitted');
        }

        const proposalId = state.proposalByHash.get(escalation.frozen_proposal_hash);
        const originalProposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
        if (originalProposal === undefined) throw new Error(`escalation ${escalationId} lost its proposal`);
        const recordEntryId = this.#ids.next('rec');
        const route =
          disposition === 'seek-review' ? 'review' : disposition === 'route-to-remedy' ? 'remedy' : null;
        const ops: WalOp[] = [
          { op: 'escalation.dispose', escalation_id: escalationId, disposition },
        ];
        if (ruling.status === 'issued') {
          ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason: `escalation-${disposition}` });
          for (const reservation of ruling.counter_reservations) {
            if (state.reservations.get(reservation.id)?.state === 'reserved') {
              ops.push({
                op: 'reservation.release',
                reservation_id: reservation.id,
                reason: `escalation-${disposition}`,
              });
            }
          }
        }
        if (disposition === 'allow-within-scope') {
          const overridePattern: PatternEvent = {
            world_id: state.worldId,
            event_id: this.#ids.next('pat'),
            mandate_id: ruling.binding.mandate_id,
            escalation_id: escalationId,
            kind: 'override',
            at,
          };
          ops.push({ op: 'pattern.record', event: overridePattern });
          ops.push(...this.#patternNarrowingOps(state, overridePattern, at, ruling.ruling_id));
        }
        ops.push({
          op: 'record.action.append',
          entry: escalationEventRecord(
            state,
            this.#systemUse,
            ruling,
            input.actor,
            recordEntryId,
            at,
            {
              event: 'human_intervention_event',
              escalation_id: escalationId,
              payload: {
                kind: 'disposition_recorded',
                disposition,
                responder_role: responderRole,
                at,
              },
            },
            route,
          ),
        });

        let reviewObligationId: string | null = null;
        if (route !== null) {
          reviewObligationId = this.#ids.next('rev');
          ops.push({
            op: 'review.open',
            obligation: {
              world_id: state.worldId,
              obligation_id: reviewObligationId,
              case_id: originalProposal.action_id,
              source_entry_id: recordEntryId,
              route,
              recovery_owner_role: escalation.contract.decision_and_route.eligible_role,
              opened_at: at,
              state: 'open',
              resolved_at: null,
            },
          });
        }

        const successorProposal = disposition === 'allow-within-scope' ? originalProposal : undefined;
        if (successorProposal === undefined) {
          return {
            ops,
            result: { accepted: true, status: 'disposed', successor: null, recordEntryId, reviewObligationId },
          };
        }

        applyWorldTransaction(state, ops, at);
        const sourceRecord = state.actionRecords.find((entry) => {
          const recordedRuling = state.rulings.get(entry.admissibility_decision.ruling_id);
          return (
            entry.authenticated_actor === 'proc:orchestrator' &&
            recordedRuling?.binding.frozen_proposal_hash === ruling.binding.frozen_proposal_hash
          );
        });
        if (sourceRecord === undefined) throw new Error(`ruling ${ruling.ruling_id} lost its action record`);
        const originalActor: TransactionActor = {
          credential: sourceRecord.authenticated_actor,
          claimed_role: sourceRecord.claimed_actor?.role ?? null,
        };
        const successorBuild = this.#buildRuling(
          {
            gate: ruling.gate,
            proposal: successorProposal,
            service: ruling.binding.service,
            actionClass: ruling.binding.action_class,
            actor: { credential: 'proc:authz', claimed_role: null },
            ...(escalation.case_id === null ? {} : { caseId: escalation.case_id }),
            context: { intervention_disposition: disposition, intervention_escalation_id: escalationId },
            signals: allowScreening.signals,
            screeningPerformed: allowScreening.performed,
            screeningEvidenceRefs: allowScreening.evidenceRefs,
          },
          state,
          at,
          {
            recordActor: { credential: 'proc:authz', claimed_role: null },
            extraBasis: [recordEntryId],
            authorizedAgentId: this.#resolveAuthorizedAgent(originalActor),
          },
        );
        const successorId = successorBuild.result.ruling.ruling_id;
        return {
          ops: [
            ...ops,
            ...successorBuild.ops,
            { op: 'ruling.link_successor', ruling_id: ruling.ruling_id, successor_ruling_id: successorId },
            { op: 'escalation.link_successor', escalation_id: escalationId, successor_ruling_id: successorId },
          ],
          result: {
            accepted: true,
            status: 'disposed',
            successor: successorBuild.result,
            recordEntryId,
            reviewObligationId,
          },
        };
      },
    );
    return completed.result;
  }

  async respondDialogue(input: RespondDialogueInput): Promise<RespondDialogueResult> {
    const escalationId = id.parse(input.escalationId);
    const disposition = input.disposition;
    const answerText = input.answerText?.trim();
    const changesConversation = ['confirm', 'correct', 'narrow', 'permit'].includes(disposition);
    const responseShapeValid =
      ((disposition !== 'correct' && disposition !== 'narrow') || (answerText !== undefined && answerText.length > 0)) &&
      (!changesConversation || input.scope?.applies_to === 'this_case_only');
    let resolvedEvidence: RegistryEvidence | null = null;
    const initialEscalation = this.#store.snapshot().escalations.get(escalationId);
    const initialResponderRole = input.actor.credential.startsWith('role:')
      ? role.safeParse(input.actor.credential.slice('role:'.length))
      : null;
    const shouldResolveEvidence =
      input.evidenceRef !== undefined &&
      disposition === 'confirm' &&
      initialEscalation?.state === 'open' &&
      initialEscalation.contract.decision_and_route.standing_class === 'third-party-fact' &&
      initialEscalation.contract.permitted_dispositions.includes(disposition) &&
      initialResponderRole?.success === true &&
      [
        initialEscalation.contract.decision_and_route.eligible_role,
        ...initialEscalation.contract.decision_and_route.substitute_roles,
      ].includes(initialResponderRole.data);
    if (shouldResolveEvidence && input.evidenceRef !== undefined) {
      try {
        timestamp.parse(input.evidenceRef.retrieved_at);
        const candidate = await this.#resolveRegistryEvidence(input.evidenceRef);
        const parsed = registryRecordRef.safeParse(candidate);
        if (
          parsed.success &&
          parsed.data.id === input.evidenceRef.id &&
          parsed.data.retrieved_at === input.evidenceRef.retrieved_at
        ) {
          resolvedEvidence = parsed.data;
        }
      } catch {
        resolvedEvidence = null;
      }
    }

    const completed = await this.#store.transactWithState<RespondDialogueResult>(
      'dialogue_response',
      input.actor,
      (state, at) => {
        const escalation = state.escalations.get(escalationId);
        if (escalation === undefined) {
          return { ops: [], result: { accepted: false, defect: 'missing-escalation', recordEntryId: null } };
        }
        const ruling = state.rulings.get(escalation.ruling_id);
        if (ruling === undefined) throw new Error(`escalation ${escalationId} lost its ruling`);
        const lateRecord = (
          terminalState: 'disposed' | 'timed_out' | 'cancelled',
        ): TransactionBuild<RespondDialogueResult> => {
          const recordEntryId = this.#ids.next('rec');
          return {
            ops: [
              {
                op: 'record.action.append',
                entry: escalationEventRecord(state, this.#systemUse, ruling, input.actor, recordEntryId, at, {
                  event: 'late_disposition_ignored',
                  escalation_id: escalationId,
                  attempted_disposition: disposition,
                  authenticated_actor: input.actor.credential,
                  terminal_state: terminalState,
                  at,
                }),
              },
            ],
            result: {
              accepted: false,
              defect: 'late-response',
              terminalState,
              recordEntryId,
            },
          };
        };
        if (escalation.state !== 'open') return lateRecord(escalation.state);

        if (at >= escalation.expires_at) {
          const appliedDefault = escalation.contract.response_bound_and_default.safe_default.disposition;
          const timeoutRecordEntryId = this.#ids.next('rec');
          const late = lateRecord('timed_out');
          const ops: WalOp[] = [
            { op: 'escalation.timeout', escalation_id: escalationId, applied_default: appliedDefault },
          ];
          if (ruling.status === 'issued') {
            if (at >= ruling.binding.validity_window.not_after) ops.push({ op: 'ruling.expire', ruling_id: ruling.ruling_id });
            else ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason: 'dialogue-timeout' });
            for (const reservation of ruling.counter_reservations) {
              if (state.reservations.get(reservation.id)?.state === 'reserved') {
                ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason: 'dialogue-timeout' });
              }
            }
          }
          ops.push({
            op: 'record.action.append',
            entry: escalationEventRecord(state, this.#systemUse, ruling, { credential: 'proc:authz', claimed_role: null }, timeoutRecordEntryId, at, {
              event: 'human_intervention_event',
              escalation_id: escalationId,
              payload: { kind: 'dialogue_timeout', applied_default: appliedDefault, at },
            }),
          });
          return { ops: [...ops, ...late.ops], result: late.result };
        }

        const refuse = (
          defect: 'wrong-role' | 'disposition-not-permitted' | 'evidence-required' | 'invalid-response',
        ): TransactionBuild<RespondDialogueResult> => {
          const recordEntryId = this.#ids.next('rec');
          const reasonCode =
            defect === 'wrong-role'
              ? 'wrong_role'
              : defect === 'disposition-not-permitted'
                ? 'disposition_not_permitted'
                : defect === 'evidence-required'
                  ? 'evidence_required'
                  : 'invalid_response';
          return {
            ops: [
              {
                op: 'record.action.append',
                entry: escalationEventRecord(state, this.#systemUse, ruling, input.actor, recordEntryId, at, {
                  event: 'human_intervention_event',
                  escalation_id: escalationId,
                  payload: { kind: 'dialogue_response_refused', reason_code: reasonCode, at },
                }),
              },
            ],
            result: { accepted: false, defect, recordEntryId },
          };
        };
        const dialogueContract = escalation.contract.permitted_dispositions.every((value) =>
          (DIALOGUE_DISPOSITIONS as readonly string[]).includes(value),
        );
        if (!dialogueContract) return refuse('disposition-not-permitted');
        const responderRole = input.actor.credential.startsWith('role:')
          ? role.parse(input.actor.credential.slice('role:'.length))
          : null;
        const eligibleRoles = [
          escalation.contract.decision_and_route.eligible_role,
          ...escalation.contract.decision_and_route.substitute_roles,
        ];
        if (responderRole === null || !eligibleRoles.includes(responderRole)) return refuse('wrong-role');
        if (!escalation.contract.permitted_dispositions.includes(disposition)) {
          return refuse('disposition-not-permitted');
        }
        if (!responseShapeValid) return refuse('invalid-response');
        if (
          disposition === 'confirm' &&
          escalation.contract.decision_and_route.standing_class === 'third-party-fact' &&
          resolvedEvidence === null
        ) {
          return refuse('evidence-required');
        }

        const sourceProposalId = state.proposalByHash.get(escalation.frozen_proposal_hash);
        const sourceProposal = sourceProposalId === undefined ? undefined : state.proposals.get(sourceProposalId);
        let sourceEntry: ConversationStoreEntry | undefined;
        if (changesConversation) {
          const itemRef = input.scope?.item_ref;
          if (escalation.case_id === null || itemRef === undefined || sourceProposal === undefined) {
            return refuse('invalid-response');
          }
          sourceEntry = state.storeItems.get(itemRef);
          const proposalItem = [...sourceProposal.material_inputs, ...sourceProposal.derived_claims].find(
            (item) => item.id === itemRef,
          );
          if (
            sourceEntry === undefined ||
            sourceEntry.case_id !== escalation.case_id ||
            proposalItem === undefined ||
            canonicalize(sourceEntry.item) !== canonicalize(proposalItem) ||
            (disposition === 'confirm' && sourceEntry.item.store !== 'inferred') ||
            (disposition === 'permit' && sourceEntry.item.store === 'inferred')
          ) {
            return refuse('invalid-response');
          }
        }

        const recordEntryId = this.#ids.next('rec');
        const ops: WalOp[] = [{ op: 'escalation.dispose', escalation_id: escalationId, disposition }];
        if (ruling.status === 'issued') {
          ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason: `dialogue-${disposition}` });
          for (const reservation of ruling.counter_reservations) {
            if (state.reservations.get(reservation.id)?.state === 'reserved') {
              ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason: `dialogue-${disposition}` });
            }
          }
        }
        ops.push({
          op: 'record.action.append',
          entry: escalationEventRecord(state, this.#systemUse, ruling, input.actor, recordEntryId, at, {
            event: 'human_intervention_event',
            escalation_id: escalationId,
            payload: {
              kind: 'dialogue_response_recorded',
              disposition,
              responder_role: responderRole,
              evidence_ref: resolvedEvidence,
              answer_digest: answerText === undefined || answerText.length === 0 ? null : sha256Hex(answerText),
              scope: input.scope ?? null,
            },
          }),
        });
        if (sourceEntry !== undefined && escalation.case_id !== null) {
          const responderOrigin =
            responderRole === 'applicant' ? 'applicant' : responderRole === 'case_officer' ? 'officer' : null;
          if (responderOrigin === null) return refuse('invalid-response');
          const turn = `dialogue_${escalationId}`;
          let answerItemId: string | null = null;
          if (answerText !== undefined && answerText.length > 0) {
            answerItemId = this.#ids.next('itm');
            ops.push({
              op: 'store.put',
              entry: {
                world_id: state.worldId,
                case_id: escalation.case_id,
                item: storeItem.parse({
                  id: answerItemId,
                  store: 'said',
                  turn,
                  text: answerText,
                  provenance: { derived_from: [sourceEntry.item.id], hops: [] },
                  tags: sourceEntry.item.tags,
                  origin_actor: responderOrigin,
                }),
              },
            });
          }
          if (disposition === 'confirm' || disposition === 'permit') {
            const derivedFrom =
              answerItemId === null ? [sourceEntry.item.id] : [sourceEntry.item.id, answerItemId];
            ops.push({
              op: 'store.put',
              entry: {
                world_id: state.worldId,
                case_id: escalation.case_id,
                item: storeItem.parse({
                  id: this.#ids.next('itm'),
                  store: disposition === 'confirm' ? 'confirmed' : 'permitted',
                  turn,
                  text: sourceEntry.item.text,
                  provenance: { derived_from: derivedFrom, hops: [] },
                  tags: sourceEntry.item.tags,
                  origin_actor: responderOrigin,
                }),
              },
            });
          }
          if (disposition === 'correct' || disposition === 'narrow') {
            ops.push({
              op: 'store.remove',
              case_id: escalation.case_id,
              item_id: sourceEntry.item.id,
              reason: `dialogue-${disposition}`,
            });
          }
        }
        let reviewObligationId: string | null = null;
        if (disposition === 'route') {
          const proposalId = state.proposalByHash.get(escalation.frozen_proposal_hash);
          const originalProposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
          if (originalProposal === undefined) throw new Error(`escalation ${escalationId} lost its proposal`);
          reviewObligationId = this.#ids.next('rev');
          ops.push({
            op: 'review.open',
            obligation: {
              world_id: state.worldId,
              obligation_id: reviewObligationId,
              case_id: originalProposal.action_id,
              source_entry_id: recordEntryId,
              route: 'review',
              recovery_owner_role: escalation.contract.decision_and_route.eligible_role,
              opened_at: at,
              state: 'open',
              resolved_at: null,
            },
          });
        }
        return {
          ops,
          result: { accepted: true, status: 'disposed', recordEntryId, reviewObligationId },
        };
      },
    );
    return completed.result;
  }

  async submitChallenge(input: SubmitChallengeInput): Promise<SubmitChallengeResult> {
    if (input.actor.credential !== 'role:applicant') {
      return { accepted: false, defect: 'wrong-role', recordEntryId: null };
    }
    const actionId = id.parse(input.actionId);
    const contestedEntryId = id.parse(input.contestedEntryId);
    const correctionText = input.correctionText.trim();
    if (correctionText.length === 0 || correctionText.length > 32_768) {
      return { accepted: false, defect: 'invalid-correction', recordEntryId: null };
    }

    const completed = await this.#store.transactWithState<SubmitChallengeResult>(
      'challenge_submit',
      input.actor,
      (state, at) => {
        const actionExists = [...state.proposals.values()].some((proposal) => proposal.action_id === actionId);
        if (!actionExists) {
          return { ops: [], result: { accepted: false, defect: 'missing-action', recordEntryId: null } };
        }
        const contestedEntry = state.actionRecords.find((entry) => entry.entry_id === contestedEntryId);
        if (contestedEntry === undefined) {
          return { ops: [], result: { accepted: false, defect: 'missing-entry', recordEntryId: null } };
        }
        const ruling = state.rulings.get(contestedEntry.admissibility_decision.ruling_id);
        if (ruling === undefined) throw new Error(`record ${contestedEntryId} lost its ruling`);
        const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
        const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
        if (proposal === undefined) throw new Error(`record ${contestedEntryId} lost its proposal`);
        if (proposal.action_id !== actionId) {
          return { ops: [], result: { accepted: false, defect: 'entry-not-in-action', recordEntryId: null } };
        }
        const existing = [...state.reviews.values()].find(
          (obligation) =>
            obligation.case_id === actionId && obligation.route === 'challenge' && obligation.state === 'open',
        );
        if (existing !== undefined) {
          return {
            ops: [],
            result: {
              accepted: false,
              defect: 'already-open',
              recordEntryId: null,
              reviewObligationId: existing.obligation_id,
            },
          };
        }

        const recordEntryId = this.#ids.next('rec');
        const reviewObligationId = this.#ids.next('rev');
        const baseRecord = escalationEventRecord(state, this.#systemUse, ruling, input.actor, recordEntryId, at, null);
        return {
          ops: [
            {
              op: 'record.action.append',
              entry: {
                ...baseRecord,
                challenge_and_remedy: {
                  route: 'challenge',
                  opened_at: at,
                  contested_entry_id: contestedEntryId,
                  correction_text: correctionText,
                  reliance_state: 'withdrawn-pending-review',
                  recovery_owner_role: 'principal',
                },
              },
            },
            {
              op: 'review.open',
              obligation: {
                world_id: state.worldId,
                obligation_id: reviewObligationId,
                case_id: actionId,
                source_entry_id: recordEntryId,
                route: 'challenge',
                recovery_owner_role: 'principal',
                opened_at: at,
                state: 'open',
                resolved_at: null,
              },
            },
          ],
          result: { accepted: true, status: 'opened', recordEntryId, reviewObligationId },
        };
      },
    );
    return completed.result;
  }

  async continueEscalationRevision(
    input: ContinueEscalationRevisionInput,
  ): Promise<ContinueEscalationRevisionResult> {
    if (input.actor.credential !== 'proc:orchestrator') {
      throw new AuthorizationError(
        'unauthorized-actor',
        'only the orchestrator may submit a revised proposal after intervention',
      );
    }
    const escalationId = id.parse(input.escalationId);
    const proposal = frozenProposal.parse(input.proposal);
    verifyProposalHash(proposal);
    const initialEscalation = this.#store.snapshot().escalations.get(escalationId);
    const screeningCaseId = initialEscalation?.case_id ?? undefined;
    const [submitScreening, verifyScreening] = await Promise.all([
      this.#screeningEvidence(proposal, 'submit', screeningCaseId),
      this.#screeningEvidence(proposal, 'verify', screeningCaseId),
    ]);
    const completed = await this.#store.transactWithState<ContinueEscalationRevisionResult>(
      'escalation_revision_continue',
      input.actor,
      (state, at) => {
        const escalation = state.escalations.get(escalationId);
        if (escalation === undefined) {
          return { ops: [], result: { accepted: false, defect: 'missing-escalation', recordEntryId: null } };
        }
        const sourceRuling = state.rulings.get(escalation.ruling_id);
        if (sourceRuling === undefined) throw new Error(`escalation ${escalationId} lost its ruling`);
        const refuse = (
          defect: 'wrong-state' | 'revision-not-permitted' | 'already-continued',
        ): TransactionBuild<ContinueEscalationRevisionResult> => {
          const recordEntryId = this.#ids.next('rec');
          return {
            ops: [
              {
                op: 'record.action.append',
                entry: escalationEventRecord(state, this.#systemUse, sourceRuling, input.actor, recordEntryId, at, {
                  event: 'human_intervention_event',
                  escalation_id: escalationId,
                  payload: {
                    kind: 'revision_continuation_refused',
                    proposal_id: proposal.proposal_id,
                    authenticated_actor: input.actor.credential,
                    reason_code:
                      defect === 'wrong-state'
                        ? 'wrong_state'
                        : defect === 'revision-not-permitted'
                          ? 'revision_not_permitted'
                          : 'already_continued',
                    at,
                  },
                }),
              },
            ],
            result: { accepted: false, defect, recordEntryId },
          };
        };
        if (escalation.state !== 'disposed' || escalation.terminal_disposition !== 'narrow-or-modify') {
          return refuse('wrong-state');
        }
        if (escalation.successor_ruling_id !== null) return refuse('already-continued');
        const dispositionRecord = state.actionRecords.find(
          (entry) =>
            entry.human_intervention_event?.event === 'human_intervention_event' &&
            entry.human_intervention_event.escalation_id === escalationId &&
            entry.human_intervention_event.payload.kind === 'disposition_recorded' &&
            entry.human_intervention_event.payload.disposition === 'narrow-or-modify',
        );
        if (dispositionRecord === undefined) {
          throw new Error(`escalation ${escalationId} lost its disposition record`);
        }
        const originalId = state.proposalByHash.get(escalation.frozen_proposal_hash);
        const original = originalId === undefined ? undefined : state.proposals.get(originalId);
        const priorAttempts = state.actionRecords
          .filter((entry) => entry.basis.includes(dispositionRecord.entry_id))
          .map((entry) => state.rulings.get(entry.admissibility_decision.ruling_id))
          .filter((ruling): ruling is GateRuling => ruling !== undefined)
          .map((ruling) => state.proposalByHash.get(ruling.binding.frozen_proposal_hash))
          .map((proposalId) => (proposalId === undefined ? undefined : state.proposals.get(proposalId)))
          .filter((candidate): candidate is FrozenProposal => candidate !== undefined);
        const latest = [original, ...priorAttempts]
          .filter((candidate): candidate is FrozenProposal => candidate !== undefined)
          .sort((left, right) => right.revision - left.revision)[0];
        if (
          original === undefined ||
          latest === undefined ||
          proposal.world_id !== original.world_id ||
          proposal.action_id !== original.action_id ||
          proposal.revision !== latest.revision + 1 ||
          proposal.proposal_id === latest.proposal_id
        ) {
          return refuse('revision-not-permitted');
        }

        const ops: WalOp[] = [];
        const stages: RuleProposalResult[] = [];
        for (const gate of ['authorize', 'submit', 'verify'] as const) {
          const screening =
            gate === 'submit'
              ? submitScreening
              : gate === 'verify'
                ? verifyScreening
                : { signals: [], performed: false, evidenceRefs: [] };
          const build = this.#buildRuling(
            {
              gate,
              proposal,
              service: sourceRuling.binding.service,
              actionClass: sourceRuling.binding.action_class,
              actor: input.actor,
              ...(escalation.case_id === null ? {} : { caseId: escalation.case_id }),
              context: {
                ...(input.context ?? {}),
                intervention_disposition: 'narrow-or-modify',
                intervention_escalation_id: escalationId,
              },
              signals: screening.signals,
              screeningPerformed: screening.performed,
              screeningEvidenceRefs: screening.evidenceRefs,
            },
            state,
            at,
            { extraBasis: [dispositionRecord.entry_id] },
          );
          ops.push(...build.ops);
          stages.push(build.result);
          // #buildRuling has already projected proposal-revision invalidations into this
          // disposable snapshot for counter evaluation. Project only the remaining ops.
          const projectionOps = build.ops.filter(
            (op) =>
              !(
                (op.op === 'ruling.invalidate' || op.op === 'reservation.release') &&
                op.reason === 'proposal-revision'
              ),
          );
          applyWorldTransaction(state, projectionOps, at);
          if (build.result.ruling.verdict !== 'allow') break;
        }
        const successor = stages.at(-1);
        if (successor === undefined) throw new Error('revision continuation produced no ruling');
        if (successor.ruling.verdict !== 'deny') {
          ops.push(
            {
              op: 'ruling.link_successor',
              ruling_id: sourceRuling.ruling_id,
              successor_ruling_id: successor.ruling.ruling_id,
            },
            {
              op: 'escalation.link_successor',
              escalation_id: escalationId,
              successor_ruling_id: successor.ruling.ruling_id,
            },
          );
        }
        return { ops, result: { accepted: true, stages, successor } };
      },
    );
    return completed.result;
  }

  async recordAccess(input: RecordAccessInput): Promise<string> {
    if (input.recorder.credential !== 'proc:authz') {
      throw new AuthorizationError('unauthorized-actor', 'only the authorization service may record HTTP access');
    }
    const entryId = this.#ids.next('acc');
    const completed = await this.#store.transactWithState('access_record', input.recorder, (state, at) => ({
      ops: [
        {
          op: 'record.access.append' as const,
          entry: accessEntry.parse({
            world_id: state.worldId,
            entry_id: entryId,
            at,
            route: input.route,
            authenticated_actor: input.authenticatedActor,
            claimed_actor: input.claimedActor,
            outcome: input.outcome,
            http_status: input.httpStatus,
            ...(input.readLengths === undefined ? {} : { read_lengths: input.readLengths }),
            ...(input.operationEvidence === undefined ? {} : { operation_evidence: input.operationEvidence }),
            ...(input.suppressedCount === undefined ? {} : { suppressed_count: input.suppressedCount }),
            ...(input.suppressionWindowMs === undefined
              ? {}
              : { suppression_window_ms: input.suppressionWindowMs }),
            ...(input.suppressionFinal === undefined ? {} : { suppression_final: input.suppressionFinal }),
          }),
        },
      ],
      result: entryId,
    }));
    return completed.result;
  }

  async commitVerify(input: CommitVerifyInput): Promise<CommitVerifyResult> {
    if (input.actor.credential !== 'proc:services_host') {
      return { ok: false, defect: 'unauthorized-caller' };
    }
    const intent = effectIntent.parse(input.intent);
    const servicesHostBootId = id.parse(input.servicesHostBootId);
    const servicesLedgerId = id.parse(input.servicesLedgerId);
    const completed = await this.#store.transactWithState<CommitVerifyResult>('commit_verify', input.actor, (state, at) => {
      const ruling = state.rulings.get(input.rulingId);
      if (ruling === undefined) return { ops: [], result: { ok: false, defect: 'replayed-ruling' } as const };
      if (ruling.status !== 'issued') {
        return { ops: [], result: { ok: false, defect: 'replayed-ruling' } as const };
      }
      if (ruling.gate !== 'commit' || ruling.verdict !== 'allow') {
        return { ops: [], result: { ok: false, defect: 'not-allowed' } as const };
      }

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
      const selection = state.modelSelections.get(ruling.binding.selection_id);
      let defect: CommitDefect | undefined;
      if (
        proposal.selection_id !== ruling.binding.selection_id ||
        selection === undefined ||
        state.currentModelSelectionByCase.get(selection.case_id) !== selection.selection_id ||
        selection.mandate_id !== ruling.binding.mandate_id ||
        selection.mandate_version !== ruling.binding.mandate_version ||
        selection.target.requested_id !== proposal.acting_model.requested_id ||
        selection.target.card_id !== proposal.acting_model.card_id ||
        selection.target.card_version !== proposal.acting_model.card_version ||
        selection.target.card_digest !== ruling.binding.card_digest ||
        selection.target.verifying_key_id !== ruling.binding.card_key_id
      ) {
        defect = 'stale-selection';
      }
      if (defect === undefined) {
        if (mandateStatus === undefined || mandateValue === undefined) {
          defect = 'missing-mandate';
        } else if (mandateStatus.version !== ruling.binding.mandate_version) {
          defect = 'invalid-mandate-binding';
        } else if (mandateStatus.state === 'revoked') {
          defect = 'revoked-mandate';
        } else if (mandateStatus.state === 'suspended') {
          defect = 'suspended-mandate';
        } else if (
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
          if (approved === undefined || approved.card_digest !== ruling.binding.card_digest) {
            defect = 'substituted-model';
          } else if (approved.re_confirmation_required === true) {
            defect = 'stale-card';
          } else {
            const currentEvidence = this.#resolveModelEvidenceFailClosed(proposal);
            if (
              !currentEvidence.servedModelAccepted ||
              currentEvidence.cardStatus !== 'current' ||
              currentEvidence.cardDigest !== ruling.binding.card_digest ||
              currentEvidence.cardKeyId !== ruling.binding.card_key_id
            ) {
              defect = 'stale-card';
            }
          }
        }
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
      if (defect === undefined && mandateValue !== undefined) {
        try {
          const currentSystemUse = this.#systemUse.resolve(
            state,
            mandateValue,
            ruling.policy_version,
            at,
          );
          if (canonicalize(currentSystemUse) !== canonicalize(ruling.binding.system_use_decision)) {
            defect = 'system-use-unavailable';
          }
        } catch (error) {
          if (error instanceof SystemUseDecisionError) defect = 'system-use-unavailable';
          else throw error;
        }
      }
      const nonce = state.nonces.get(ruling.binding.nonce);
      if (defect === undefined && (nonce === undefined || nonce.state !== 'issued')) defect = 'replayed-ruling';
      if (defect === undefined) {
        let deltas: Partial<Record<CounterName, number>>;
        try {
          deltas = requestedDeltas({
            gate: ruling.gate,
            proposal,
            service: ruling.binding.service,
            actionClass: ruling.binding.action_class,
            actor: input.actor,
          });
        } catch {
          deltas = {};
          defect = 'counter-invalid';
        }
        if (defect === undefined && !rulingReservationsMatchDeltas(ruling, deltas)) defect = 'counter-invalid';
      }
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

      const effectRequestDigest = digestFor('effect-intent', intent);
      const systemUseDecision = committedSystemUseReference(ruling);
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
            services_host_boot_id: servicesHostBootId,
            services_ledger_id: servicesLedgerId,
            system_use_decision: systemUseDecision,
            system_use_current_at_bind: true,
            recovery_contract: this.#policy.policy.recovery_escalation_contract,
            state: 'bound',
            outcome: null,
            recovery_owner_role: this.#policy.policy.recovery_escalation_contract.decision_and_route.eligible_role,
          },
        },
        {
          op: 'record.action.append',
          entry: commitmentRecordEntry(
            state,
            this.#systemUse,
            ruling,
            input.actor,
            recordEntryId,
            commitmentId,
            effectId,
            idempotencyKey,
            effectRequestDigest,
            servicesLedgerId,
            at,
            tokenExpiresAt,
          ),
        },
      );
      return { ops, result: { ok: true, token, commitmentId, recordEntryId } as const };
    });
    return completed.result;
  }

  async reportEffectOutcome(input: EffectOutcomeReportInput): Promise<EffectOutcomeReportResult> {
    const serviceReport = input.actor.credential === 'proc:services_host' && input.delivery !== 'reconciliation-probe';
    const reconciliationReport =
      input.actor.credential === 'proc:authz' && input.delivery === 'reconciliation-probe';
    if (!serviceReport && !reconciliationReport) {
      return { accepted: false, defect: 'unauthorized-reporter' };
    }
    const reportWorldId = worldId.parse(input.worldId);
    const commitmentId = id.parse(input.commitmentId);
    const effectId = id.parse(input.effectId);
    const idempotencyKey = hexDigest.parse(input.idempotencyKey);
    const effectRequestDigest = hexDigest.parse(input.effectRequestDigest);
    const servicesHostBootId = id.parse(input.servicesHostBootId);
    const servicesLedgerId = id.parse(input.servicesLedgerId);
    const recordedAt = timestamp.parse(input.recordedAt);

    const completed = await this.#store.transactWithState<EffectOutcomeReportResult>(
      'effect_outcome',
      input.actor,
      (state, at) => {
        const commitment = state.commitments.get(commitmentId);
        if (commitment === undefined) {
          return { ops: [], result: { accepted: false, defect: 'missing-commitment' } as const };
        }
        if (
          state.worldId !== reportWorldId ||
          commitment.effect_id !== effectId ||
          commitment.idempotency_key !== idempotencyKey ||
          commitment.effect_request_digest !== effectRequestDigest ||
          commitment.services_host_boot_id !== servicesHostBootId ||
          commitment.services_ledger_id !== servicesLedgerId
        ) {
          return { ops: [], result: { accepted: false, defect: 'binding-mismatch' } as const };
        }

        const existing = state.effects.get(effectId);
        if (existing !== undefined) {
          if (
            existing.commitment_id !== commitmentId ||
            existing.idempotency_key !== idempotencyKey ||
            existing.effect_request_digest !== effectRequestDigest ||
            existing.outcome !== input.outcome
          ) {
            return { ops: [], result: { accepted: false, defect: 'conflicting-outcome' } as const };
          }
          if (input.delivery !== 'retry') {
            return {
              ops: [],
              result: { accepted: true, status: 'already-recorded', recordEntryId: null } as const,
            };
          }
          const retryEntryId = this.#ids.next('rec');
          return {
            ops: [
              {
                op: 'record.action.append',
                entry: commitmentEventRecordEntry(state, this.#systemUse, commitment, input.actor, retryEntryId, at, {
                  event: 'retry_served',
                  effect_id: effectId,
                  idempotency_key: idempotencyKey,
                  served_at: at,
                  recorded_outcome: input.outcome,
                }),
              },
            ],
            result: { accepted: true, status: 'retry-recorded', recordEntryId: retryEntryId } as const,
          };
        }
        if (commitment.state !== 'bound' && commitment.state !== 'unknown') {
          return { ops: [], result: { accepted: false, defect: 'terminal-commitment' } as const };
        }

        const ruling = state.rulings.get(commitment.ruling_id);
        if (ruling === undefined) throw new Error(`commitment ${commitmentId} lost its ruling`);
        const recordEntryId = this.#ids.next('rec');
        const systemUseCurrent = this.#systemUse.isReferenceCurrent(state, commitment.system_use_decision, at);
        const ops: WalOp[] = [
          {
            op: 'effect.record',
            effect: {
              world_id: state.worldId,
              effect_id: effectId,
              commitment_id: commitmentId,
              idempotency_key: idempotencyKey,
              effect_request_digest: effectRequestDigest,
              services_ledger_id: servicesLedgerId,
              system_use_decision: commitment.system_use_decision,
              system_use_current_at_record: systemUseCurrent,
              outcome: input.outcome,
              recorded_at: recordedAt,
              ...(input.detail === undefined ? {} : { detail: input.detail }),
            },
          },
        ];
        if (commitment.state === 'bound') {
          ops.push({ op: 'commitment.discharge', commitment_id: commitmentId, outcome: input.outcome });
        } else {
          for (const reservation of ruling.counter_reservations) {
            if (state.reservations.get(reservation.id)?.state === 'held_for_reconciliation') {
              ops.push({ op: 'reservation.reconcile', reservation_id: reservation.id, resolution: 'settled' });
            }
          }
          ops.push({ op: 'commitment.reconcile', commitment_id: commitmentId, resolution: input.outcome });
          const recovery = [...state.escalations.values()].find(
            (value) => value.source_commitment_id === commitmentId && value.state === 'open',
          );
          if (recovery !== undefined) ops.push({ op: 'escalation.cancel', escalation_id: recovery.escalation_id });
        }
        ops.push({
          op: 'record.action.append',
          entry: commitmentEventRecordEntry(state, this.#systemUse, commitment, input.actor, recordEntryId, at, {
            event: 'effect_outcome',
            effect_id: effectId,
            outcome: input.outcome,
            reported_at: at,
            recovery_owner_role: null,
            system_use_decision: commitment.system_use_decision,
            system_use_current_at_record: systemUseCurrent,
            ...(input.detail === undefined ? {} : { detail: input.detail }),
          }),
        });
        return {
          ops,
          result: { accepted: true, status: 'recorded', recordEntryId } as const,
        };
      },
    );
    return completed.result;
  }

  async reconcileCommitment(options: ReconcileCommitmentOptions): Promise<ReconcileCommitmentResult> {
    const commitmentId = id.parse(options.commitmentId);
    const attempts = options.attempts ?? 3;
    const backoff = options.backoffMs ?? [250, 1_000, 4_000];
    const delay =
      options.delay ?? ((milliseconds: number) => new Promise<void>((resolve) => setTimeout(resolve, milliseconds)));
    if (!Number.isSafeInteger(attempts) || attempts <= 0) {
      throw new RangeError('reconciliation attempts must be a positive safe integer');
    }
    if (
      backoff.length === 0 ||
      backoff.some((value) => !Number.isSafeInteger(value) || value < 0)
    ) {
      throw new RangeError('reconciliation backoff values must be non-negative safe integers');
    }

    const initial = this.#store.snapshot().commitments.get(commitmentId);
    if (initial === undefined) return { resolution: 'already-terminal' };
    if (initial.state === 'discharged' || initial.state === 'reconciled') {
      return { resolution: 'already-terminal' };
    }

    for (let attempt = 0; attempt < attempts; attempt += 1) {
      let probe: CommitmentProbe | undefined;
      try {
        probe = await options.probe(initial.idempotency_key);
      } catch {
        // An unreachable probe cannot prove absence. Retry, then route as unknown.
      }
      if (probe?.state === 'recorded') {
        const report = await this.reportEffectOutcome({
          worldId: probe.record.world_id,
          commitmentId,
          effectId: probe.record.effect_id,
          idempotencyKey: probe.record.idempotency_key,
          effectRequestDigest: probe.record.effect_request_digest,
          servicesHostBootId: probe.record.services_host_boot_id,
          servicesLedgerId: probe.record.services_ledger_id,
          outcome: probe.record.outcome,
          recordedAt: probe.record.recorded_at,
          ...(probe.record.detail === undefined ? {} : { detail: probe.record.detail }),
          delivery: 'reconciliation-probe',
          actor: { credential: 'proc:authz', claimed_role: null },
        });
        return { resolution: 'recorded', report };
      }
      if (
        probe?.state === 'absent' &&
        probe.ledger_id === initial.services_ledger_id &&
        probe.boot_id !== initial.services_host_boot_id
      ) {
        const result = await this.reconcileAbsentAfterRestart(commitmentId, probe.boot_id, probe.ledger_id);
        if (!result.ok && result.defect === 'effect-already-recorded') {
          return { resolution: 'already-terminal' };
        }
        return { resolution: 'absent-after-restart', result };
      }
      if (attempt + 1 < attempts) {
        const wait = backoff[Math.min(attempt, backoff.length - 1)] as number;
        await delay(wait);
      }
    }
    const latest = this.#store.snapshot().commitments.get(commitmentId);
    if (latest === undefined || latest.state === 'discharged' || latest.state === 'reconciled') {
      return { resolution: 'already-terminal' };
    }
    return { resolution: 'unknown', result: await this.markCommitmentUnknown(commitmentId) };
  }

  async markCommitmentUnknown(
    commitmentIdInput: string,
    actor: TransactionActor = { credential: 'proc:authz', claimed_role: null },
  ): Promise<MarkUnknownResult> {
    if (actor.credential !== 'proc:authz') return { ok: false, defect: 'unauthorized-reporter' };
    const commitmentId = id.parse(commitmentIdInput);
    const completed = await this.#store.transactWithState<MarkUnknownResult>(
      'commitment_unknown',
      actor,
      (state, at) => {
        const commitment = state.commitments.get(commitmentId);
        if (commitment === undefined) return { ops: [], result: { ok: false, defect: 'missing-commitment' } as const };
        const existingRecovery = [...state.escalations.values()].find(
          (value) => value.source_commitment_id === commitmentId,
        );
        if (commitment.state === 'unknown' && existingRecovery?.state === 'open') {
          return {
            ops: [],
            result: { ok: true, status: 'already-open', escalationId: existingRecovery.escalation_id } as const,
          };
        }
        if (commitment.state !== 'bound') {
          return { ops: [], result: { ok: false, defect: 'terminal-commitment' } as const };
        }
        const ruling = state.rulings.get(commitment.ruling_id);
        if (ruling === undefined) throw new Error(`commitment ${commitmentId} lost its ruling`);
        const escalationId = this.#ids.next('esc');
        const recordEntryId = this.#ids.next('rec');
        const contract = commitment.recovery_contract;
        const expiresAt = addMilliseconds(at, contract.response_bound_and_default.response_bound_ms);
        const ops: WalOp[] = [];
        for (const reservation of ruling.counter_reservations) {
          if (state.reservations.get(reservation.id)?.state === 'settled') {
            ops.push({ op: 'reservation.hold_for_reconciliation', reservation_id: reservation.id });
          }
        }
        ops.push(
          {
            op: 'commitment.mark_unknown',
            commitment_id: commitmentId,
            recovery_owner_role: commitment.recovery_owner_role,
          },
          {
            op: 'escalation.open',
            escalation: {
              world_id: state.worldId,
              escalation_id: escalationId,
              case_id: null,
              ruling_id: commitment.ruling_id,
              source_commitment_id: commitmentId,
              frozen_proposal_hash: commitment.frozen_proposal_hash,
              contract,
              opened_at: at,
              expires_at: expiresAt,
              state: 'open',
              terminal_disposition: null,
              successor_ruling_id: null,
            },
          },
          {
            op: 'record.action.append',
            entry: commitmentEventRecordEntry(
              state,
              this.#systemUse,
              commitment,
              actor,
              recordEntryId,
              at,
              {
                event: 'effect_outcome',
                effect_id: commitment.effect_id,
                outcome: 'unknown-reconciliation-required',
                reported_at: at,
                recovery_owner_role: commitment.recovery_owner_role,
                system_use_decision: commitment.system_use_decision,
                system_use_current_at_record: this.#systemUse.isReferenceCurrent(state, commitment.system_use_decision, at),
                detail: 'No durable service outcome was available after bounded reconciliation probes.',
              },
              {
                event: 'human_intervention_event',
                escalation_id: escalationId,
                payload: {
                  kind: 'escalation_raised',
                  contract,
                  reason: 'The effect outcome is unknown and requires a recovery finding.',
                },
              },
            ),
          },
        );
        return { ops, result: { ok: true, status: 'opened', escalationId } as const };
      },
    );
    return completed.result;
  }

  async reconcileAbsentAfterRestart(
    commitmentIdInput: string,
    observedServicesHostBootIdInput: string,
    observedServicesLedgerIdInput: string,
    actor: TransactionActor = { credential: 'proc:authz', claimed_role: null },
  ): Promise<ReconcileAbsentResult> {
    if (actor.credential !== 'proc:authz') return { ok: false, defect: 'unauthorized-reporter' };
    const commitmentId = id.parse(commitmentIdInput);
    const observedBootId = id.parse(observedServicesHostBootIdInput);
    const observedLedgerId = id.parse(observedServicesLedgerIdInput);
    const completed = await this.#store.transactWithState<ReconcileAbsentResult>(
      'commitment_reconcile_absent',
      actor,
      (state, at) => {
        const commitment = state.commitments.get(commitmentId);
        if (commitment === undefined) return { ops: [], result: { ok: false, defect: 'missing-commitment' } as const };
        if (commitment.state === 'reconciled' && commitment.outcome === 'no-effect') {
          return {
            ops: [],
            result: { ok: true, status: 'already-reconciled', recordEntryId: null } as const,
          };
        }
        if (observedBootId === commitment.services_host_boot_id) {
          return { ops: [], result: { ok: false, defect: 'host-still-running' } as const };
        }
        if (observedLedgerId !== commitment.services_ledger_id) {
          return { ops: [], result: { ok: false, defect: 'ledger-continuity-mismatch' } as const };
        }
        if (state.effects.has(commitment.effect_id)) {
          return { ops: [], result: { ok: false, defect: 'effect-already-recorded' } as const };
        }
        if (commitment.state !== 'bound' && commitment.state !== 'unknown') {
          return { ops: [], result: { ok: false, defect: 'terminal-commitment' } as const };
        }
        const ruling = state.rulings.get(commitment.ruling_id);
        if (ruling === undefined) throw new Error(`commitment ${commitmentId} lost its ruling`);
        const recordEntryId = this.#ids.next('rec');
        const ops: WalOp[] = [];
        if (commitment.state === 'bound') {
          for (const reservation of ruling.counter_reservations) {
            if (state.reservations.get(reservation.id)?.state === 'settled') {
              ops.push({ op: 'reservation.hold_for_reconciliation', reservation_id: reservation.id });
            }
          }
          ops.push({
            op: 'commitment.mark_unknown',
            commitment_id: commitmentId,
            recovery_owner_role: commitment.recovery_owner_role,
          });
        }
        ops.push({ op: 'commitment.reconcile', commitment_id: commitmentId, resolution: 'no-effect' });
        for (const reservation of ruling.counter_reservations) {
          const reservationState = state.reservations.get(reservation.id)?.state;
          if (reservationState === 'held_for_reconciliation' || reservationState === 'settled') {
            ops.push({ op: 'reservation.reconcile', reservation_id: reservation.id, resolution: 'released' });
          }
        }
        const recovery = [...state.escalations.values()].find(
          (value) => value.source_commitment_id === commitmentId && value.state === 'open',
        );
        if (recovery !== undefined) ops.push({ op: 'escalation.cancel', escalation_id: recovery.escalation_id });
        ops.push({
          op: 'record.action.append',
          entry: commitmentEventRecordEntry(state, this.#systemUse, commitment, actor, recordEntryId, at, {
            event: 'effect_outcome',
            effect_id: commitment.effect_id,
            outcome: 'no-effect',
            reported_at: at,
            recovery_owner_role: null,
            system_use_decision: commitment.system_use_decision,
            system_use_current_at_record: this.#systemUse.isReferenceCurrent(state, commitment.system_use_decision, at),
            detail: 'The services host restarted without a committed idempotency-ledger entry.',
          }),
        });
        return { ops, result: { ok: true, status: 'reconciled', recordEntryId } as const };
      },
    );
    return completed.result;
  }
}
