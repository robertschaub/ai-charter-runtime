// SPDX-License-Identifier: AGPL-3.0-only
/** M5.2 projections, M5.3 output admission, and M5.5 durable model-call lifecycle. */
import { randomUUID } from 'node:crypto';

import { canonicalize } from './canonicalize.js';
import { modelCallStart, type ModelCallStart } from './authorizationProjection.js';
import { CardRegistry, type CardInspection } from './cardRegistry.js';
import { projectConversation, type ProjectConversationInput } from './conversationProjection.js';
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
} from './schemas/index.js';
import { screeningFixtureSet, type ScreeningFixture } from './screeningFixture.js';
import { mandateVersionKey, type WorldState } from './state.js';
import type { TransactionActor, WalStore } from './walStore.js';
import { SystemUseDecisionError, SystemUseDecisionService } from './systemUseDecision.js';

export class ConversationProjectionServiceError extends Error {
  constructor(
    readonly code: 'forbidden' | 'invalid-scope' | 'mandate-unavailable' | 'model-unavailable' | 'system-use-unavailable',
    message: string,
  ) {
    super(message);
    this.name = 'ConversationProjectionServiceError';
  }
}

export interface ActingProjectionInput {
  readonly mandateId: string;
  readonly mandateVersion: number;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly requestedId: string;
  readonly actor: TransactionActor;
}

export interface ScreeningProjectionInput {
  readonly proposal: FrozenProposal;
  readonly gate: 'submit' | 'verify';
  readonly caseId?: string;
}

export type ModelCallBeginInput = ModelCallBeginRequest & { readonly actor: TransactionActor };
export type ModelCallCompletionInput = ModelCallAdmissionRequest & { readonly actor: TransactionActor };
export type ModelCallFailureInput = ModelCallFailureRequest & { readonly actor: TransactionActor };

export interface ConversationProjectionServiceOptions {
  readonly store: WalStore;
  readonly cards: CardRegistry;
  readonly keyring: Keyring;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly screeningFixtures: readonly ScreeningFixture[];
  readonly now?: () => string;
  readonly modelCallTtlMs?: number;
  readonly systemUse: SystemUseDecisionService;
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
  readonly #systemUse: SystemUseDecisionService;

  constructor(options: ConversationProjectionServiceOptions) {
    this.#store = options.store;
    this.#cards = options.cards;
    this.#keyring = options.keyring;
    this.#caseId = id.parse(options.caseId);
    this.#authorizationBootId = id.parse(options.authorizationBootId);
    this.#fixtures = screeningFixtureSet.parse(options.screeningFixtures);
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#modelCallTtlMs = integer.min(1).max(300_000).parse(options.modelCallTtlMs ?? 60_000);
    this.#systemUse = options.systemUse;
  }

  async beginCall(input: ModelCallBeginInput): Promise<ModelCallStart> {
    const { actor, ...requestInput } = input;
    const request = modelCallBeginRequest.parse(requestInput);
    const callId = id.parse(`mcl_${randomUUID()}`);
    const completed = await this.#store.transactWithState<ModelCallStart>('model_call_begin', actor, (state, at) => {
      const resolved = this.#resolveActing(
        {
          mandateId: request.mandate_id,
          mandateVersion: request.mandate_version,
          cardId: request.card_id,
          cardVersion: request.card_version,
          requestedId: request.requested_id,
          actor,
        },
        state,
        at,
      );
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
        mandate_id: request.mandate_id,
        mandate_version: request.mandate_version,
        card_id: request.card_id,
        card_version: request.card_version,
        requested_id: request.requested_id,
        projection_digest: digestFor('conversation-projection', resolved.projection),
        projection_item_count: resolved.projection.items.length,
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
    actor: TransactionActor,
    state?: WorldState,
    nowInput?: string,
    expectedSystemUse?: ModelCallOpenRecord['system_use_decision'],
  ): ModelOutputAdmission {
    const resolved = this.#resolveActing(
      {
        mandateId: request.mandate_id,
        mandateVersion: request.mandate_version,
        cardId: request.card_id,
        cardVersion: request.card_version,
        requestedId: request.requested_id,
        actor,
      },
      state,
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
      call.mandate_id === failure.mandate_id &&
      call.mandate_version === failure.mandate_version &&
      call.card_id === failure.card_id &&
      call.card_version === failure.card_version &&
      call.requested_id === failure.requested_id &&
      verifyDigest(call.projection_digest, failure.projection_digest)
    );
  }

  async completeCall(input: ModelCallCompletionInput): Promise<ModelCallAdmission> {
    const { actor, ...requestInput } = input;
    const request = modelCallAdmissionRequest.parse(requestInput);
    const completed = await this.#store.transactWithState<ModelCallAdmission>(
      'model_call_complete',
      actor,
      (state, at) => {
        const call = this.#openCall(state, request.call_id, at);
        if (!this.#callMatchesOutput(call, request.output)) {
          throw new ConversationProjectionServiceError('invalid-scope', 'model output does not match its call attempt');
        }
        const decision = this.#evaluateOutput(request.output, actor, state, at, call.system_use_decision);
        const admission = modelCallAdmission.parse({ kind: 'model_call_admission', call_id: call.call_id, decision });
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
          ],
          result: admission,
        };
      },
    );
    return completed.result;
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
      return {
        ops: [
          {
            op: 'model_call.fail',
            call_id: call.call_id,
            provider_disclosure: request.provider_disclosure,
            served_id: request.served_id,
            failure_reason: request.failure_reason,
            completed_at: at,
          },
        ],
        result: failed,
      };
    });
    return completed.result;
  }

  #resolveActing(input: ActingProjectionInput, state?: WorldState, nowInput?: string): {
    readonly projection: ReturnType<typeof projectConversation>;
    readonly inspection: CardInspection;
    readonly systemUseDecision: ModelCallOpenRecord['system_use_decision'];
  } {
    if (input.actor.credential !== 'proc:orchestrator') {
      throw new ConversationProjectionServiceError('forbidden', 'only the orchestrator process may read acting projection');
    }
    const mandateId = id.parse(input.mandateId);
    const mandateVersion = integer.min(1).parse(input.mandateVersion);
    const currentState = state ?? this.#store.snapshot();
    const currentTime = timestamp.parse(nowInput ?? this.#now());
    const governingMandate = this.#singleActiveMandate(currentState, currentTime);
    if (governingMandate.mandate_id !== mandateId || governingMandate.version !== mandateVersion) {
      throw new ConversationProjectionServiceError(
        'invalid-scope',
        'acting projection mandate does not match the sole active mandate',
      );
    }
    return this.#resolveProjection(
      {
        mandateId,
        mandateVersion,
        cardId: cardSlug.parse(input.cardId),
        cardVersion: integer.min(1).parse(input.cardVersion),
        requestedId: modelId.parse(input.requestedId),
        role: 'acting',
        caseId: this.#caseId,
      },
      currentState,
      currentTime,
    );
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
      systemUseDecision,
    };
  }

  #project(input: ResolvedProjectionInput): ReturnType<typeof projectConversation> {
    return this.#resolveProjection(input).projection;
  }
}
