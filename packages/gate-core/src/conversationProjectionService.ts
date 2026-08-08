// SPDX-License-Identifier: AGPL-3.0-only
/** M5.2 projections, M5.3 output admission, and M5.5 durable model-call lifecycle. */
import { randomUUID } from 'node:crypto';

import { canonicalize } from './canonicalize.js';
import {
  approvedModelProjection,
  currentModelSelectionProjection,
  modelCallStart,
  modelSelectionCheckProjection,
  modelSelectionProjection,
  type CurrentModelSelectionProjection,
  type ModelCallStart,
  type ModelSelectionCheckProjection,
  type ModelSelectionProjection,
} from './authorizationProjection.js';
import { CardRegistry, type CardInspection } from './cardRegistry.js';
import { intersectClearances, projectConversation, type ProjectConversationInput } from './conversationProjection.js';
import { evaluateModelOutput, ModelOutputAdmissionError } from './modelOutputAdmission.js';
import { digestFor, verifyDigest } from './hash.js';
import { verifyEmbeddedMac, type Keyring } from './keyring.js';
import type { ScreeningResolution } from './authorizationCore.js';
import {
  cardSlug,
  id,
  integer,
  modelId,
  modelCallAdmission,
  modelCallAdmissionRequest,
  modelCallBeginRequest,
  modelCallFailedRecord,
  modelCallFailureRequest,
  modelCallOpenRecord,
  modelSelectionCheckRecord,
  modelSelectionCheckRequest,
  modelSelectionRequest,
  modelSelectionResult,
  modelSelectionTransition,
  timestamp,
  type EvidenceRef,
  type FrozenProposal,
  type Mandate,
  type ModelRole,
  type ModelOutputAdmission,
  type ModelOutputAdmissionRequest,
  type ModelCallAdmission,
  type ModelCallAdmissionRequest,
  type ModelCallBeginRequest,
  type ModelCallFailedRecord,
  type ModelCallFailureRequest,
  type ModelCallOpenRecord,
  type ModelSelectionCheckRequest,
  type BoundModelSelectionTarget,
  type ModelSelectionRequest,
  type ModelSelectionTransition,
  type WalOp,
} from './schemas/index.js';
import { screeningFixtureSet, type ScreeningFixture } from './screeningFixture.js';
import { mandateVersionKey, type WorldState } from './state.js';
import type { TransactionActor, WalStore } from './walStore.js';
import { SystemUseDecisionError, SystemUseDecisionService } from './systemUseDecision.js';
import { compareServedId } from './servedModel.js';
import { ConversationTransportService } from './conversationTransport.js';
import { ProposalIntakeService } from './proposalIntake.js';
import { outputReleaseInvalidationOps, proposalIntakeInvalidationOps } from './conversationInvalidation.js';

export class ConversationProjectionServiceError extends Error {
  constructor(
    readonly code:
      | 'forbidden'
      | 'invalid-scope'
      | 'mandate-unavailable'
      | 'model-unavailable'
      | 'selection-unavailable'
      | 'system-use-unavailable',
    message: string,
  ) {
    super(message);
    this.name = 'ConversationProjectionServiceError';
  }
}

export interface ScreeningProjectionInput {
  readonly proposal: FrozenProposal;
  readonly gate: 'submit' | 'verify';
  readonly caseId?: string;
}

export type ModelCallBeginInput = Omit<ModelCallBeginRequest, 'ingress_binding' | 'proposal_binding'> & {
  readonly ingress_binding?: ModelCallBeginRequest['ingress_binding'];
  readonly proposal_binding?: ModelCallBeginRequest['proposal_binding'];
  readonly sessionId?: string;
  readonly actor: TransactionActor;
};
export type ModelCallCompletionInput = ModelCallAdmissionRequest & {
  readonly sessionId?: string;
  readonly actor: TransactionActor;
};
export type ModelCallFailureInput = ModelCallFailureRequest & { readonly actor: TransactionActor };

type ModelCallCompletionTransaction =
  | { readonly kind: 'admission'; readonly admission: ModelCallAdmission }
  | { readonly kind: 'system-use-invalidated'; readonly failure: ModelCallFailedRecord };

export interface ConversationProjectionServiceOptions {
  readonly store: WalStore;
  readonly cards: CardRegistry;
  readonly keyring: Keyring;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly screeningFixtures: readonly ScreeningFixture[];
  readonly now?: () => string;
  readonly modelCallTtlMs?: number;
  readonly modelSelectionCheckTtlMs?: number;
  readonly systemUse: SystemUseDecisionService;
  readonly conversationTransport?: ConversationTransportService;
  readonly proposalIntakes?: ProposalIntakeService;
}

interface ResolvedProjectionInput {
  readonly mandateId: string;
  readonly mandateVersion: number;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly requestedId: string;
  readonly role: ModelRole;
  readonly caseId: string;
  readonly entries?: ProjectConversationInput['entries'];
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function projectionEvidence(projection: ReturnType<typeof projectConversation>): EvidenceRef {
  return {
    kind: 'submit_projection',
    provider: projection.provider,
    role: projection.role,
    included: projection.summary.included,
    dropped: projection.summary.dropped,
    dropped_item_ids: projection.summary.dropped_item_ids,
    unmet_tags: projection.summary.unmet_tags,
  };
}

function skippedEvidence(
  reason: Extract<EvidenceRef, { kind: 'screening_skipped' }>['reason'],
  provider: string | null,
  suspectItemIds: readonly string[],
): EvidenceRef {
  return {
    kind: 'screening_skipped',
    provider: provider === null ? null : cardSlug.parse(provider),
    role: 'screening',
    reason,
    suspect_item_ids: sorted(suspectItemIds),
  };
}

/**
 * No caller supplies a case, role, item list, or effective clearance. Acting projection
 * fixes case and role at this boundary; screening selection comes only from an exact
 * authorization-owned fixture over a frozen proposal hash.
 */
export class ConversationProjectionService {
  readonly #store: WalStore;
  readonly #cards: CardRegistry;
  readonly #keyring: Keyring;
  readonly #caseId: string;
  readonly #authorizationBootId: string;
  readonly #fixtures: readonly ScreeningFixture[];
  readonly #now: () => string;
  readonly #modelCallTtlMs: number;
  readonly #modelSelectionCheckTtlMs: number;
  readonly #systemUse: SystemUseDecisionService;
  readonly #conversationTransport: ConversationTransportService | undefined;
  readonly #proposalIntakes: ProposalIntakeService | undefined;

  constructor(options: ConversationProjectionServiceOptions) {
    this.#store = options.store;
    this.#cards = options.cards;
    this.#keyring = options.keyring;
    this.#caseId = id.parse(options.caseId);
    this.#authorizationBootId = id.parse(options.authorizationBootId);
    this.#fixtures = screeningFixtureSet.parse(options.screeningFixtures);
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#modelCallTtlMs = integer.min(1).max(300_000).parse(options.modelCallTtlMs ?? 60_000);
    this.#modelSelectionCheckTtlMs = integer
      .min(1)
      .max(300_000)
      .parse(options.modelSelectionCheckTtlMs ?? 300_000);
    this.#systemUse = options.systemUse;
    this.#conversationTransport = options.conversationTransport;
    this.#proposalIntakes = options.proposalIntakes;
  }

  #requireOrchestrator(actor: TransactionActor): void {
    if (actor.credential !== 'proc:orchestrator') {
      throw new ConversationProjectionServiceError('forbidden', 'only the orchestrator process may use model selection');
    }
  }

  #currentSelection(state: WorldState): ModelSelectionTransition | null {
    const selectionId = state.currentModelSelectionByCase.get(this.#caseId);
    if (selectionId === undefined) return null;
    const selection = state.modelSelections.get(selectionId);
    if (selection === undefined || selection.case_id !== this.#caseId) {
      throw new ConversationProjectionServiceError('selection-unavailable', 'current model selection is inconsistent');
    }
    return selection;
  }

  currentSelection(actor: TransactionActor): CurrentModelSelectionProjection {
    this.#requireOrchestrator(actor);
    const state = this.#store.snapshot();
    const selection = this.#currentSelection(state);
    if (selection === null) {
      return currentModelSelectionProjection.parse({
        state: 'unselected',
        authorization_boot_id: this.#authorizationBootId,
        case_id: this.#caseId,
        selection: null,
        latest_observation: null,
      });
    }
    const latestObservation = [...state.modelSelectionObservations.values()]
      .filter((value) => value.selection_id === selection.selection_id)
      .sort(
        (left, right) =>
          right.observed_at.localeCompare(left.observed_at) || right.observation_id.localeCompare(left.observation_id),
      )[0] ?? null;
    return currentModelSelectionProjection.parse({
      state: 'selected',
      authorization_boot_id: this.#authorizationBootId,
      case_id: this.#caseId,
      selection,
      latest_observation: latestObservation,
    });
  }

  async checkSelection(
    input: ModelSelectionCheckRequest & { readonly actor: TransactionActor },
  ): Promise<ModelSelectionCheckProjection> {
    const { actor, ...requestInput } = input;
    this.#requireOrchestrator(actor);
    const request = modelSelectionCheckRequest.parse(requestInput);
    const checkId = id.parse(`msc_${randomUUID()}`);
    const completed = await this.#store.transactWithState<ModelSelectionCheckProjection>(
      'model_selection_check',
      actor,
      (state, at) => {
        const current = this.#currentSelection(state);
        if ((current?.selection_id ?? null) !== request.expected_current_selection_id) {
          throw new ConversationProjectionServiceError('selection-unavailable', 'expected selection is not current');
        }
        const mandateValue = this.#singleActiveMandate(state, at);
        const resolved = this.#resolveProjection(
          {
            mandateId: mandateValue.mandate_id,
            mandateVersion: mandateValue.version,
            cardId: request.target.card_id,
            cardVersion: request.target.card_version,
            requestedId: request.target.requested_id,
            role: 'acting',
            caseId: this.#caseId,
          },
          state,
          at,
        );
        if (resolved.approval.re_confirmation_required === true || state.policy === undefined) {
          throw new ConversationProjectionServiceError('model-unavailable', 'target model requires principal re-confirmation');
        }
        const check = modelSelectionCheckRecord.parse({
          kind: 'model_selection_check',
          world_id: state.worldId,
          check_id: checkId,
          authorization_boot_id: this.#authorizationBootId,
          case_id: this.#caseId,
          authenticated_actor: actor.credential,
          expected_current_selection_id: request.expected_current_selection_id,
          mandate_id: mandateValue.mandate_id,
          mandate_version: mandateValue.version,
          target: {
            ...request.target,
            card_digest: resolved.approval.card_digest,
            verifying_key_id: resolved.inspection.keyId,
          },
          system_use_decision: resolved.systemUseDecision,
          policy_version: state.policy.policy_version,
          policy_content_digest: state.policy.policy_content_digest,
          evaluator_build_id: state.policy.evaluator_build_id,
          issued_at: at,
          expires_at: timestamp.parse(new Date(Date.parse(at) + this.#modelSelectionCheckTtlMs).toISOString()),
          state: 'issued',
          consumed_at: null,
        });
        const evidence = approvedModelProjection.parse({
          approval: resolved.approval,
          effective_data_classes: {
            acting: intersectClearances(
              resolved.approval.data_classes.acting ?? [],
              resolved.inspection.card.declared_data_classes.acting ?? [],
            ),
          },
          card_status: 'current',
          signature_status: 'valid',
          integrity_alarm: false,
          current_card_digest: resolved.inspection.digest,
          verifying_key_id: resolved.inspection.keyId,
          current_card: resolved.inspection.card,
        });
        return {
          ops: [{ op: 'model_selection_check.issue', check }],
          result: modelSelectionCheckProjection.parse({ check, evidence }),
        };
      },
    );
    return completed.result;
  }

  async selectModel(
    input: ModelSelectionRequest & { readonly actor: TransactionActor },
  ): Promise<ModelSelectionProjection> {
    const { actor, ...requestInput } = input;
    this.#requireOrchestrator(actor);
    const request = modelSelectionRequest.parse(requestInput);
    const selectionId = id.parse(`sel_${randomUUID()}`);
    type SelectionBuild =
      | { readonly accepted: true; readonly projection: ModelSelectionProjection }
      | { readonly accepted: false; readonly reason: string };
    const completed = await this.#store.transactWithState<SelectionBuild>(
      'model_selection_apply',
      actor,
      (state, at) => {
        const check = state.modelSelectionChecks.get(request.check_id);
        if (check === undefined || check.state !== 'issued') {
          return { ops: [], result: { accepted: false, reason: 'selection check is unavailable' } };
        }
        if (at >= check.expires_at) {
          return {
            ops: [{ op: 'model_selection_check.expire', check_id: check.check_id }],
            result: { accepted: false, reason: 'selection check expired' },
          };
        }
        if (
          check.authorization_boot_id !== this.#authorizationBootId ||
          check.case_id !== this.#caseId ||
          check.authenticated_actor !== actor.credential ||
          check.expected_current_selection_id !== request.expected_current_selection_id
        ) {
          return { ops: [], result: { accepted: false, reason: 'selection check binding changed' } };
        }
        const current = this.#currentSelection(state);
        if ((current?.selection_id ?? null) !== request.expected_current_selection_id) {
          return { ops: [], result: { accepted: false, reason: 'selection predecessor is stale' } };
        }
        const mandateValue = this.#singleActiveMandate(state, at);
        const resolved = this.#resolveProjection(
          {
            mandateId: mandateValue.mandate_id,
            mandateVersion: mandateValue.version,
            cardId: check.target.card_id,
            cardVersion: check.target.card_version,
            requestedId: check.target.requested_id,
            role: 'acting',
            caseId: this.#caseId,
          },
          state,
          at,
        );
        const target: BoundModelSelectionTarget = {
          card_id: resolved.approval.card_id,
          card_version: resolved.approval.card_version,
          requested_id: resolved.approval.requested_id,
          card_digest: resolved.approval.card_digest,
          verifying_key_id: resolved.inspection.keyId,
        };
        if (
          resolved.approval.re_confirmation_required === true ||
          mandateValue.mandate_id !== check.mandate_id ||
          mandateValue.version !== check.mandate_version ||
          canonicalize(target) !== canonicalize(check.target) ||
          canonicalize(resolved.systemUseDecision) !== canonicalize(check.system_use_decision) ||
          state.policy === undefined ||
          state.policy.policy_version !== check.policy_version ||
          state.policy.policy_content_digest !== check.policy_content_digest ||
          state.policy.evaluator_build_id !== check.evaluator_build_id
        ) {
          return { ops: [], result: { accepted: false, reason: 'selection authority changed after check' } };
        }
        if (current === null) {
          if (
            mandateValue.default_acting_model.card_id !== check.target.card_id ||
            mandateValue.default_acting_model.card_version !== check.target.card_version ||
            mandateValue.default_acting_model.requested_id !== check.target.requested_id
          ) {
            return { ops: [], result: { accepted: false, reason: 'initial selection is not the mandate default' } };
          }
        } else if (
          canonicalize(current.target) === canonicalize(target) &&
          current.mandate_id === mandateValue.mandate_id &&
          current.mandate_version === mandateValue.version &&
          canonicalize(current.system_use_decision) === canonicalize(resolved.systemUseDecision)
        ) {
          return { ops: [], result: { accepted: false, reason: 'model is already selected' } };
        }

        const reason = 'model-selection-switch';
        const invalidationOps: WalOp[] = [];
        let invalidatedRulings = 0;
        if (current !== null) {
          for (const ruling of state.rulings.values()) {
            if (ruling.status !== 'issued' || ruling.binding.selection_id !== current.selection_id) continue;
            invalidatedRulings += 1;
            invalidationOps.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason });
            for (const reservation of ruling.counter_reservations) {
              if (state.reservations.get(reservation.id)?.state === 'reserved') {
                invalidationOps.push({ op: 'reservation.release', reservation_id: reservation.id, reason });
              }
            }
          }
        }
        const openCalls =
          current === null
            ? []
            : [...state.modelCalls.values()].filter(
                (call) => call.state === 'open' && call.selection_id === current.selection_id,
              );
        for (const call of openCalls) {
          invalidationOps.push({
            op: 'model_call.fail',
            call_id: call.call_id,
            provider_disclosure: 'possible',
            served_id: null,
            failure_reason: 'selection-invalidated',
            completed_at: at,
          });
        }
        const selection = modelSelectionTransition.parse({
          world_id: state.worldId,
          selection_id: selectionId,
          case_id: this.#caseId,
          kind: current === null ? 'initial' : 'switch',
          predecessor_selection_id: current?.selection_id ?? null,
          mandate_id: mandateValue.mandate_id,
          mandate_version: mandateValue.version,
          target,
          system_use_decision: resolved.systemUseDecision,
          check_id: check.check_id,
          selected_at: at,
          authority_effect: 'none',
        });
        const projection = modelSelectionResult.parse({
          kind: 'model_selection_result',
          selection,
          invalidated_ruling_count: invalidatedRulings,
          terminalized_open_call_count: openCalls.length,
        });
        return {
          ops: [
            { op: 'model_selection_check.consume', check_id: check.check_id, consumed_at: at },
            ...invalidationOps,
            ...outputReleaseInvalidationOps(
              state,
              (release) => release.case_id === this.#caseId,
              'model-selection-changed',
              at,
            ),
            ...proposalIntakeInvalidationOps(
              state,
              (intake) => intake.case_id === this.#caseId,
              'binding-invalidated',
              at,
            ),
            { op: 'model_selection.append', selection },
          ],
          result: { accepted: true, projection },
        };
      },
    );
    if (!completed.result.accepted) {
      throw new ConversationProjectionServiceError('selection-unavailable', completed.result.reason);
    }
    return completed.result.projection;
  }

  async beginCall(input: ModelCallBeginInput): Promise<ModelCallStart> {
    const { actor, sessionId, ...requestInput } = input;
    const request = modelCallBeginRequest.parse(requestInput);
    const callId = id.parse(`mcl_${randomUUID()}`);
    const completed = await this.#store.transactWithState<ModelCallStart>('model_call_begin', actor, (state, at) => {
      this.#requireOrchestrator(actor);
      const selection = state.modelSelections.get(request.selection_id);
      if (
        selection === undefined ||
        selection.case_id !== this.#caseId ||
        state.currentModelSelectionByCase.get(this.#caseId) !== selection.selection_id
      ) {
        throw new ConversationProjectionServiceError('selection-unavailable', 'model call selection is not current');
      }
      const currentMandate = this.#singleActiveMandate(state, at);
      if (currentMandate.mandate_id !== selection.mandate_id || currentMandate.version !== selection.mandate_version) {
        throw new ConversationProjectionServiceError('selection-unavailable', 'model selection mandate is no longer sole and active');
      }
      const resolved = this.#resolveProjection(
        {
          mandateId: selection.mandate_id,
          mandateVersion: selection.mandate_version,
          cardId: selection.target.card_id,
          cardVersion: selection.target.card_version,
          requestedId: selection.target.requested_id,
          role: 'acting',
          caseId: this.#caseId,
        },
        state,
        at,
      );
      if (canonicalize(resolved.systemUseDecision) !== canonicalize(selection.system_use_decision)) {
        throw new ConversationProjectionServiceError('system-use-unavailable', 'selection system-use decision is stale');
      }
      if (request.ingress_binding !== null) {
        if (this.#conversationTransport === undefined || sessionId === undefined) {
          throw new ConversationProjectionServiceError('invalid-scope', 'message-bound call requires session provenance');
        }
        try {
          this.#conversationTransport.assertIngressBinding(
            state,
            at,
            request.ingress_binding,
            request.turn_id,
            sessionId,
            resolved.projection,
          );
        } catch {
          throw new ConversationProjectionServiceError('invalid-scope', 'message ingress binding is unavailable');
        }
      }
      if (request.proposal_binding !== null) {
        if (this.#proposalIntakes === undefined || sessionId === undefined) {
          throw new ConversationProjectionServiceError('invalid-scope', 'proposal-purpose call requires session provenance');
        }
        try {
          this.#proposalIntakes.assertCallBinding(
            state,
            at,
            request.proposal_binding,
            sessionId,
            resolved.projection,
          );
        } catch {
          throw new ConversationProjectionServiceError('invalid-scope', 'proposal-purpose binding is unavailable');
        }
      }
      if ([...state.modelCalls.values()].some((call) => call.case_id === this.#caseId && call.turn_id === request.turn_id)) {
        throw new ConversationProjectionServiceError('invalid-scope', 'model turn already has a durable call attempt');
      }
      const call = modelCallOpenRecord.parse({
        kind: 'model_call_lifecycle',
        world_id: state.worldId,
        call_id: callId,
        authorization_boot_id: this.#authorizationBootId,
        case_id: this.#caseId,
        turn_id: request.turn_id,
        selection_id: selection.selection_id,
        mandate_id: selection.mandate_id,
        mandate_version: selection.mandate_version,
        card_id: selection.target.card_id,
        card_version: selection.target.card_version,
        requested_id: selection.target.requested_id,
        projection_digest: digestFor('conversation-projection', resolved.projection),
        projection_item_count: resolved.projection.items.length,
        projection_item_ids: resolved.projection.items.map((item) => item.id),
        ingress_binding: request.ingress_binding,
        proposal_binding: request.proposal_binding,
        session_id:
          request.ingress_binding === null && request.proposal_binding === null
            ? null
            : id.parse(sessionId),
        system_use_decision: resolved.systemUseDecision,
        opened_at: at,
        expires_at: timestamp.parse(new Date(Date.parse(at) + this.#modelCallTtlMs).toISOString()),
        state: 'open',
        outcome: 'indeterminate',
        provider_disclosure: 'possible',
        completed_at: null,
        served_id: null,
        output_digest: null,
        failure_reason: null,
      });
      return {
        ops: [{ op: 'model_call.open', call }],
        result: modelCallStart.parse({ call, projection: resolved.projection }),
      };
    });
    return completed.result;
  }

  #evaluateOutput(
    request: ModelOutputAdmissionRequest,
    state?: WorldState,
    nowInput?: string,
    expectedSystemUse?: ModelCallOpenRecord['system_use_decision'],
  ): ModelOutputAdmission {
    const currentState = state ?? this.#store.snapshot();
    const selection = currentState.modelSelections.get(request.selection_id);
    if (
      selection === undefined ||
      selection.case_id !== this.#caseId ||
      currentState.currentModelSelectionByCase.get(this.#caseId) !== selection.selection_id ||
      selection.mandate_id !== request.mandate_id ||
      selection.mandate_version !== request.mandate_version ||
      selection.target.card_id !== request.card_id ||
      selection.target.card_version !== request.card_version ||
      selection.target.requested_id !== request.requested_id
    ) {
      throw new ConversationProjectionServiceError('selection-unavailable', 'model output selection is not current');
    }
    const currentMandate = this.#singleActiveMandate(currentState, nowInput);
    if (currentMandate.mandate_id !== selection.mandate_id || currentMandate.version !== selection.mandate_version) {
      throw new ConversationProjectionServiceError('selection-unavailable', 'model selection mandate is no longer sole and active');
    }
    const resolved = this.#resolveProjection(
      {
        mandateId: selection.mandate_id,
        mandateVersion: selection.mandate_version,
        cardId: selection.target.card_id,
        cardVersion: selection.target.card_version,
        requestedId: selection.target.requested_id,
        role: 'acting',
        caseId: this.#caseId,
      },
      currentState,
      nowInput,
    );
    if (
      expectedSystemUse !== undefined &&
      canonicalize(resolved.systemUseDecision) !== canonicalize(expectedSystemUse)
    ) {
      throw new ConversationProjectionServiceError('system-use-unavailable', 'system-use decision changed after call open');
    }
    try {
      return evaluateModelOutput({
        request,
        caseId: this.#caseId,
        projection: resolved.projection,
        resolutionPolicy: resolved.inspection.card.model.resolution.policy,
        observedServedIds: resolved.inspection.card.model.resolution.observed_snapshots.map((entry) => entry.id),
      });
    } catch (error) {
      if (error instanceof ModelOutputAdmissionError) {
        throw new ConversationProjectionServiceError('invalid-scope', 'model output does not match the current acting projection');
      }
      throw error;
    }
  }

  #openCall(state: WorldState, callIdInput: string, at: string): ModelCallOpenRecord {
    const callId = id.parse(callIdInput);
    const call = state.modelCalls.get(callId);
    if (
      call === undefined ||
      call.state !== 'open' ||
      call.authorization_boot_id !== this.#authorizationBootId ||
      state.currentModelSelectionByCase.get(call.case_id) !== call.selection_id ||
      at > call.expires_at
    ) {
      throw new ConversationProjectionServiceError('invalid-scope', 'model call attempt is unavailable');
    }
    return call;
  }

  #callMatchesOutput(call: ModelCallOpenRecord, output: ModelOutputAdmissionRequest): boolean {
    return (
      call.case_id === this.#caseId &&
      call.turn_id === output.turn_id &&
      call.selection_id === output.selection_id &&
      call.mandate_id === output.mandate_id &&
      call.mandate_version === output.mandate_version &&
      call.card_id === output.card_id &&
      call.card_version === output.card_version &&
      call.requested_id === output.requested_id &&
      verifyDigest(call.projection_digest, output.projection_digest)
    );
  }

  #callMatchesFailure(call: ModelCallOpenRecord, failure: ModelCallFailureRequest): boolean {
    return (
      call.case_id === this.#caseId &&
      call.turn_id === failure.turn_id &&
      call.selection_id === failure.selection_id &&
      verifyDigest(call.projection_digest, failure.projection_digest)
    );
  }

  #selectionObservationOp(
    state: WorldState,
    call: ModelCallOpenRecord,
    servedId: string,
    terminalOutcome: 'admitted' | 'withheld' | 'failed',
    observedAt: string,
    knownResolution?: 'exact' | 'benign-resolution' | 'mismatch',
  ): WalOp {
    const selection = state.modelSelections.get(call.selection_id);
    if (selection === undefined) {
      throw new ConversationProjectionServiceError('selection-unavailable', 'model call lost its selection');
    }
    const inspection = this.#cards.get(selection.target.card_id);
    const resolution =
      knownResolution ??
      (inspection === undefined
        ? 'mismatch'
        : compareServedId(selection.target.requested_id, inspection.card.model.resolution.policy, servedId));
    return {
      op: 'model_selection.observe',
      observation: {
        kind: 'model_selection_observation',
        world_id: state.worldId,
        observation_id: id.parse(`mso_${randomUUID()}`),
        selection_id: selection.selection_id,
        call_id: call.call_id,
        served_id: servedId,
        model_resolution: resolution,
        terminal_outcome: terminalOutcome,
        observed_at: observedAt,
      },
    };
  }

  async completeCall(input: ModelCallCompletionInput): Promise<ModelCallAdmission> {
    const { actor, sessionId, ...requestInput } = input;
    this.#requireOrchestrator(actor);
    const request = modelCallAdmissionRequest.parse(requestInput);
    const completed = await this.#store.transactWithState<ModelCallCompletionTransaction>(
      'model_call_complete',
      actor,
      (state, at) => {
        const call = this.#openCall(state, request.call_id, at);
        if (
          (call.ingress_binding !== null || call.proposal_binding !== null) &&
          (sessionId === undefined || call.session_id !== id.parse(sessionId))
        ) {
          throw new ConversationProjectionServiceError('invalid-scope', 'purpose-bound call session does not match');
        }
        if (!this.#callMatchesOutput(call, request.output)) {
          throw new ConversationProjectionServiceError('invalid-scope', 'model output does not match its call attempt');
        }
        let decision: ModelCallAdmission['decision'];
        try {
          decision = this.#evaluateOutput(request.output, state, at, call.system_use_decision);
        } catch (error) {
          if (!(error instanceof ConversationProjectionServiceError) || error.code !== 'system-use-unavailable') {
            throw error;
          }
          const failure = modelCallFailedRecord.parse({
            ...call,
            state: 'terminal',
            outcome: 'failed',
            provider_disclosure: 'confirmed',
            completed_at: at,
            served_id: request.output.served_id,
            output_digest: null,
            failure_reason: 'system-use-invalidated',
          });
          return {
            ops: [
              {
                op: 'model_call.fail',
                call_id: call.call_id,
                provider_disclosure: 'confirmed',
                served_id: request.output.served_id,
                failure_reason: 'system-use-invalidated',
                completed_at: at,
              },
              this.#selectionObservationOp(state, call, request.output.served_id, 'failed', at),
            ],
            result: { kind: 'system-use-invalidated', failure },
          };
        }
        let release: ReturnType<ConversationTransportService['prepareRelease']> | null = null;
        let proposalIntake: ReturnType<ProposalIntakeService['prepareIntake']> | null = null;
        if (decision.disposition === 'admitted' && call.ingress_binding !== null) {
          if (this.#conversationTransport === undefined) {
            throw new ConversationProjectionServiceError('invalid-scope', 'conversation transport is unavailable');
          }
          try {
            release = this.#conversationTransport.prepareRelease(state, at, call, decision);
          } catch {
            throw new ConversationProjectionServiceError('invalid-scope', 'output release currentness failed');
          }
        }
        if (decision.disposition === 'admitted' && call.proposal_binding !== null) {
          if (this.#proposalIntakes === undefined) {
            throw new ConversationProjectionServiceError('invalid-scope', 'proposal intake is unavailable');
          }
          try {
            proposalIntake = this.#proposalIntakes.prepareIntake(state, at, call, decision);
          } catch {
            throw new ConversationProjectionServiceError('invalid-scope', 'proposal intake currentness failed');
          }
        }
        const admission = modelCallAdmission.parse({
          kind: 'model_call_admission',
          call_id: call.call_id,
          decision,
          release: release?.reference ?? null,
          proposal_intake: proposalIntake?.reference ?? null,
        });
        return {
          ops: [
            {
              op: 'model_call.complete',
              call_id: call.call_id,
              outcome: decision.disposition,
              served_id: decision.served_id,
              output_digest: decision.output_digest,
              completed_at: at,
            },
            this.#selectionObservationOp(
              state,
              call,
              decision.served_id,
              decision.disposition,
              at,
              decision.model_resolution,
            ),
            ...(release === null ? [] : [release.op]),
            ...(proposalIntake === null ? [] : [proposalIntake.op]),
          ],
          result: { kind: 'admission', admission },
        };
      },
    );
    if (completed.result.kind === 'system-use-invalidated') {
      throw new ConversationProjectionServiceError(
        'system-use-unavailable',
        'served response was durably refused because the bound system-use decision changed',
      );
    }
    return completed.result.admission;
  }

  async failCall(input: ModelCallFailureInput): Promise<ModelCallFailedRecord> {
    const { actor, ...requestInput } = input;
    if (actor.credential !== 'proc:orchestrator') {
      throw new ConversationProjectionServiceError('forbidden', 'only the orchestrator process may report model-call failure');
    }
    const request = modelCallFailureRequest.parse(requestInput);
    const completed = await this.#store.transactWithState<ModelCallFailedRecord>('model_call_fail', actor, (state, at) => {
      const call = this.#openCall(state, request.call_id, at);
      if (!this.#callMatchesFailure(call, request)) {
        throw new ConversationProjectionServiceError('invalid-scope', 'model failure does not match its call attempt');
      }
      if (request.failure_reason === 'system-use-invalidated') {
        if (request.provider_disclosure === 'confirmed') {
          throw new ConversationProjectionServiceError(
            'invalid-scope',
            'confirmed system-use invalidation is derived only from an output-admission request',
          );
        }
        const mandateValue = state.mandates.get(mandateVersionKey(call.mandate_id, call.mandate_version));
        let stillCurrent = false;
        if (mandateValue !== undefined && state.policy !== undefined) {
          try {
            stillCurrent =
              canonicalize(this.#systemUse.resolve(state, mandateValue, state.policy.policy_version, at)) ===
              canonicalize(call.system_use_decision);
          } catch (error) {
            if (!(error instanceof SystemUseDecisionError)) throw error;
          }
        }
        if (stillCurrent) {
          throw new ConversationProjectionServiceError(
            'invalid-scope',
            'system-use-invalidated requires evidence that the bound decision is no longer current',
          );
        }
      }
      const failed = modelCallFailedRecord.parse({
        ...call,
        state: 'terminal',
        outcome: 'failed',
        provider_disclosure: request.provider_disclosure,
        completed_at: at,
        served_id: request.served_id,
        output_digest: null,
        failure_reason: request.failure_reason,
      });
      const ops: WalOp[] = [
        {
            op: 'model_call.fail',
            call_id: call.call_id,
            provider_disclosure: request.provider_disclosure,
            served_id: request.served_id,
            failure_reason: request.failure_reason,
            completed_at: at,
        },
      ];
      if (request.provider_disclosure === 'confirmed' && request.served_id !== null) {
        ops.push(this.#selectionObservationOp(state, call, request.served_id, 'failed', at));
      }
      return {
        ops,
        result: failed,
      };
    });
    return completed.result;
  }

  screening(input: ScreeningProjectionInput): ScreeningResolution {
    const fixture = this.#fixtures.find(
      (candidate) => candidate.proposal_hash === input.proposal.proposal_hash && candidate.gate === input.gate,
    );
    if (fixture === undefined) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence('fixture-unavailable', null, [])],
      };
    }
    const caseId = input.caseId ?? this.#caseId;
    if (caseId !== this.#caseId) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence('case-mismatch', fixture.provider, fixture.suspect_item_ids)],
      };
    }

    const proposalItems = new Map(
      [...input.proposal.material_inputs, ...input.proposal.derived_claims].map((item) => [item.id, item]),
    );
    const state = this.#store.snapshot();
    const selectedEntries = fixture.suspect_item_ids.flatMap((itemId) => {
      const proposalItem = proposalItems.get(itemId);
      const entry = state.storeItems.get(itemId);
      return proposalItem !== undefined &&
        entry !== undefined &&
        entry.case_id === this.#caseId &&
        canonicalize(proposalItem) === canonicalize(entry.item)
        ? [entry]
        : [];
    });
    if (selectedEntries.length !== fixture.suspect_item_ids.length) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence('proposal-item-mismatch', fixture.provider, fixture.suspect_item_ids)],
      };
    }

    let projection: ReturnType<typeof projectConversation>;
    try {
      projection = this.#project({
        mandateId: input.proposal.mandate_ref.mandate_id,
        mandateVersion: input.proposal.mandate_ref.version,
        cardId: fixture.provider,
        cardVersion: this.#approvedVersion(input.proposal.mandate_ref.mandate_id, fixture.provider, 'screening'),
        requestedId: this.#approvedRequestedId(input.proposal.mandate_ref.mandate_id, fixture.provider, 'screening'),
        role: 'screening',
        caseId: this.#caseId,
        entries: selectedEntries,
      });
    } catch (error) {
      const reason =
        error instanceof ConversationProjectionServiceError && error.code === 'mandate-unavailable'
          ? 'mandate-unavailable'
          : 'model-unavailable';
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence(reason, fixture.provider, fixture.suspect_item_ids)],
      };
    }
    const projectionRef = projectionEvidence(projection);
    if (projection.summary.dropped > 0 || projection.items.length !== fixture.suspect_item_ids.length) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [projectionRef, skippedEvidence('disclosure-restricted', fixture.provider, fixture.suspect_item_ids)],
      };
    }
    return { performed: true, signals: fixture.signals, evidenceRefs: [projectionRef] };
  }

  validateScreeningResolution(
    resolution: ScreeningResolution,
    proposal: FrozenProposal,
    gate: 'submit' | 'verify',
    caseId?: string,
  ): boolean {
    return canonicalize(this.screening({ proposal, gate, ...(caseId === undefined ? {} : { caseId }) })) ===
      canonicalize(resolution);
  }

  #currentMandate(
    mandateIdInput: string,
    versionInput?: number,
    stateInput?: WorldState,
    nowInput?: string,
  ): Mandate {
    const mandateId = id.parse(mandateIdInput);
    const state = stateInput ?? this.#store.snapshot();
    const status = state.mandateStatus.get(mandateId);
    const version = versionInput ?? status?.version;
    const mandateValue = version === undefined ? undefined : state.mandates.get(mandateVersionKey(mandateId, version));
    const now = timestamp.parse(nowInput ?? this.#now());
    if (
      status === undefined ||
      mandateValue === undefined ||
      status.version !== version ||
      status.state !== 'active' ||
      mandateValue.state !== 'active' ||
      now < mandateValue.issued_at ||
      now > mandateValue.expires_at ||
      now < mandateValue.limits.time_window.not_before ||
      now > mandateValue.limits.time_window.not_after ||
      verifyEmbeddedMac(
        this.#keyring,
        'mandate-binding',
        mandateValue as unknown as Record<string, unknown>,
        'binding',
      ) !== 'valid'
    ) {
      throw new ConversationProjectionServiceError('mandate-unavailable', 'mandate is not current and active');
    }
    return mandateValue;
  }

  #singleActiveMandate(stateInput?: WorldState, nowInput?: string): Mandate {
    const state = stateInput ?? this.#store.snapshot();
    const active = [...state.mandateStatus.entries()].filter(
      ([, status]) => status.state === 'active',
    );
    if (active.length !== 1) {
      throw new ConversationProjectionServiceError(
        'mandate-unavailable',
        'acting projection requires exactly one active mandate in the bounded POC world',
      );
    }
    const [mandateId, status] = active[0] as (typeof active)[number];
    return this.#currentMandate(mandateId, status.version, state, nowInput);
  }

  #approvedVersion(mandateId: string, cardId: string, role: ModelRole): number {
    const approval = this.#currentMandate(mandateId).approved_models.find(
      (candidate) => candidate.card_id === cardId && candidate.roles.includes(role),
    );
    if (approval === undefined) {
      throw new ConversationProjectionServiceError('model-unavailable', `model ${cardId} is not approved for ${role}`);
    }
    return approval.card_version;
  }

  #approvedRequestedId(mandateId: string, cardId: string, role: ModelRole): string {
    const approval = this.#currentMandate(mandateId).approved_models.find(
      (candidate) => candidate.card_id === cardId && candidate.roles.includes(role),
    );
    if (approval === undefined) {
      throw new ConversationProjectionServiceError('model-unavailable', `model ${cardId} is not approved for ${role}`);
    }
    return approval.requested_id;
  }

  #resolveProjection(input: ResolvedProjectionInput, stateInput?: WorldState, nowInput?: string): {
    readonly projection: ReturnType<typeof projectConversation>;
    readonly inspection: CardInspection;
    readonly approval: Mandate['approved_models'][number];
    readonly systemUseDecision: ModelCallOpenRecord['system_use_decision'];
  } {
    if (input.caseId !== this.#caseId) {
      throw new ConversationProjectionServiceError('invalid-scope', 'projection case does not match authorization configuration');
    }
    const state = stateInput ?? this.#store.snapshot();
    const mandateValue = this.#currentMandate(input.mandateId, input.mandateVersion, state, nowInput);
    let systemUseDecision: ModelCallOpenRecord['system_use_decision'];
    try {
      if (state.policy === undefined) {
        throw new SystemUseDecisionError('scope-mismatch', 'active policy is unavailable');
      }
      systemUseDecision = this.#systemUse.resolve(state, mandateValue, state.policy.policy_version, nowInput ?? this.#now());
    } catch (error) {
      if (error instanceof SystemUseDecisionError) {
        throw new ConversationProjectionServiceError('system-use-unavailable', 'current system-use decision is unavailable');
      }
      throw error;
    }
    const approval = mandateValue.approved_models.find(
      (candidate) =>
        candidate.card_id === input.cardId &&
        candidate.card_version === input.cardVersion &&
        candidate.requested_id === input.requestedId &&
        candidate.roles.includes(input.role),
    );
    const inspection = this.#cards.get(input.cardId);
    if (
      approval === undefined ||
      inspection === undefined ||
      !inspection.signatureValid ||
      inspection.withdrawn ||
      inspection.integrityAlarm ||
      inspection.card.card_version !== approval.card_version ||
      inspection.card.model.requested_id !== approval.requested_id ||
      inspection.digest !== approval.card_digest
    ) {
      throw new ConversationProjectionServiceError('model-unavailable', 'approved model card is unavailable or changed');
    }
    const mandateClearances = approval.data_classes[input.role];
    const cardClearances = inspection.card.declared_data_classes[input.role];
    if (mandateClearances === undefined || cardClearances === undefined) {
      throw new ConversationProjectionServiceError('model-unavailable', `model lacks ${input.role} clearance`);
    }
    return {
      projection: projectConversation({
        worldId: mandateValue.world_id,
        caseId: this.#caseId,
        provider: approval.card_id,
        role: input.role,
        mandateClearances,
        cardClearances,
        entries: input.entries ?? [...state.storeItems.values()],
      }),
      inspection,
      approval,
      systemUseDecision,
    };
  }

  #project(input: ResolvedProjectionInput): ReturnType<typeof projectConversation> {
    return this.#resolveProjection(input).projection;
  }
}
