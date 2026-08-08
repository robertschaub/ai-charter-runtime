// SPDX-License-Identifier: AGPL-3.0-only
/** M5.10 authorization-owned conversation ingress and single-use output release. */
import { randomUUID } from 'node:crypto';

import { canonicalize } from './canonicalize.js';
import { CardRegistry, type CardInspection } from './cardRegistry.js';
import { intersectClearances, projectConversation, unionRestrictionTags } from './conversationProjection.js';
import { conversationMutationInvalidationOps } from './conversationInvalidation.js';
import { digestFor, verifyDigest } from './hash.js';
import { verifyEmbeddedMac, type Keyring } from './keyring.js';
import { digestModelOutput } from './modelOutputAdmission.js';
import {
  CASE_OFFICER_MESSAGE_PROFILE_ID,
  CASE_OFFICER_MESSAGE_PROFILE,
  CASE_OFFICER_MESSAGE_TAGS,
  conversationIngressEvent,
  conversationMessageIngressRequest,
  conversationMessageIngressResult,
  conversationProcessProjection,
  id,
  integer,
  modelCallIngressBinding,
  modelOutputAdmissionRequest,
  outputReleaseConsumeResult,
  outputReleaseRecord,
  outputReleaseReference,
  outputReleaseStatusProjection,
  storeItem,
  timestamp,
  type ConversationMessageIngressRequest,
  type ConversationMessageIngressResult,
  type ConversationProcessEvent,
  type ConversationProcessProjection,
  type Mandate,
  type ModelCallIngressBinding,
  type ModelCallOpenRecord,
  type ModelOutputAdmission,
  type OutputReleaseConsumeResult,
  type OutputReleaseRecord,
  type OutputReleaseReference,
  type OutputReleaseStatusProjection,
  type WalOp,
} from './schemas/index.js';
import { mandateVersionKey, type WorldState } from './state.js';
import { SystemUseDecisionService } from './systemUseDecision.js';
import type { TransactionActor, WalStore } from './walStore.js';

const MAX_MESSAGE_BYTES = 8_192;
const MAX_CONVERSATION_EVENTS = 128;
const MAX_CONVERSATION_BYTES = 256 * 1_024;

export const CASE_OFFICER_MESSAGE_PROFILE_DIGEST = digestFor(
  'conversation-ingress-profile',
  CASE_OFFICER_MESSAGE_PROFILE,
);

export class ConversationTransportError extends Error {
  constructor(
    readonly code:
      | 'forbidden'
      | 'invalid-message'
      | 'invalid-scope'
      | 'conflict'
      | 'capacity'
      | 'unavailable'
      | 'currentness',
    message: string,
  ) {
    super(message);
    this.name = 'ConversationTransportError';
  }
}

export interface ConversationTransportServiceOptions {
  readonly store: WalStore;
  readonly cards: CardRegistry;
  readonly keyring: Keyring;
  readonly systemUse: SystemUseDecisionService;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly now?: () => string;
  readonly releaseTtlMs?: number;
  readonly nextMessageItemId?: () => string;
  readonly nextEventId?: () => string;
  readonly nextReleaseId?: () => string;
}

interface CurrentGovernance {
  readonly mandate: Mandate;
  readonly approval: Mandate['approved_models'][number];
  readonly inspection: CardInspection;
  readonly selection: WorldState['modelSelections'] extends Map<string, infer T> ? T : never;
}

interface PreparedRelease {
  readonly op: Extract<WalOp, { readonly op: 'output_release.issue' }>;
  readonly reference: OutputReleaseReference;
}

interface ConsumptionFailure {
  readonly kind: 'failure';
  readonly message: string;
}

interface ConsumptionSuccess {
  readonly kind: 'success';
  readonly result: OutputReleaseConsumeResult;
}

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function validateMessageText(value: string): number {
  const bytes = Buffer.byteLength(value, 'utf8');
  if (
    !isWellFormedUnicode(value) ||
    !/\S/u.test(value) ||
    bytes > MAX_MESSAGE_BYTES ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    throw new ConversationTransportError('invalid-message', 'message does not satisfy the bounded text contract');
  }
  return bytes;
}

function contentDigest(caseId: string, itemId: string, text: string): string {
  return digestFor('conversation-item-content', { case_id: caseId, item_id: itemId, text });
}

export class ConversationTransportService {
  readonly #store: WalStore;
  readonly #cards: CardRegistry;
  readonly #keyring: Keyring;
  readonly #systemUse: SystemUseDecisionService;
  readonly #caseId: string;
  readonly #authorizationBootId: string;
  readonly #now: () => string;
  readonly #releaseTtlMs: number;
  readonly #nextMessageItemId: () => string;
  readonly #nextEventId: () => string;
  readonly #nextReleaseId: () => string;

  constructor(options: ConversationTransportServiceOptions) {
    this.#store = options.store;
    this.#cards = options.cards;
    this.#keyring = options.keyring;
    this.#systemUse = options.systemUse;
    this.#caseId = id.parse(options.caseId);
    this.#authorizationBootId = id.parse(options.authorizationBootId);
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#releaseTtlMs = integer.min(1).max(120_000).parse(options.releaseTtlMs ?? 120_000);
    this.#nextMessageItemId = options.nextMessageItemId ?? (() => `itm_${randomUUID()}`);
    this.#nextEventId = options.nextEventId ?? (() => `cve_${randomUUID()}`);
    this.#nextReleaseId = options.nextReleaseId ?? (() => `orl_${randomUUID()}`);
  }

  #requireOrchestrator(actor: TransactionActor): void {
    if (actor.credential !== 'proc:orchestrator') {
      throw new ConversationTransportError('forbidden', 'only the orchestrator process may use conversation transport');
    }
  }

  #receipt(state: WorldState, sessionIdInput: string, at: string) {
    const sessionId = id.parse(sessionIdInput);
    const receipt = state.caseSessionProvenance.get(sessionId);
    if (
      receipt === undefined ||
      receipt.state !== 'active' ||
      receipt.world_id !== state.worldId ||
      receipt.case_id !== this.#caseId ||
      receipt.role !== 'case_officer' ||
      receipt.authorization_boot_id !== this.#authorizationBootId ||
      at >= receipt.expires_at
    ) {
      throw new ConversationTransportError('forbidden', 'case-session provenance is unavailable');
    }
    return receipt;
  }

  #currentGovernance(state: WorldState, at: string): CurrentGovernance {
    const selectionId = state.currentModelSelectionByCase.get(this.#caseId);
    const selection = selectionId === undefined ? undefined : state.modelSelections.get(selectionId);
    if (selection === undefined || selection.case_id !== this.#caseId) {
      throw new ConversationTransportError('currentness', 'current model selection is unavailable');
    }
    const active = [...state.mandateStatus.entries()].filter(([, status]) => status.state === 'active');
    if (active.length !== 1) {
      throw new ConversationTransportError('currentness', 'exactly one active mandate is required');
    }
    const [mandateId, status] = active[0] as (typeof active)[number];
    const mandate = state.mandates.get(mandateVersionKey(mandateId, status.version));
    if (
      mandate === undefined ||
      mandate.mandate_id !== selection.mandate_id ||
      mandate.version !== selection.mandate_version ||
      mandate.state !== 'active' ||
      at < mandate.issued_at ||
      at > mandate.expires_at ||
      at < mandate.limits.time_window.not_before ||
      at > mandate.limits.time_window.not_after ||
      verifyEmbeddedMac(this.#keyring, 'mandate-binding', mandate as unknown as Record<string, unknown>, 'binding') !==
        'valid'
    ) {
      throw new ConversationTransportError('currentness', 'current mandate is unavailable');
    }
    const approval = mandate.approved_models.find(
      (candidate) =>
        candidate.card_id === selection.target.card_id &&
        candidate.card_version === selection.target.card_version &&
        candidate.requested_id === selection.target.requested_id &&
        candidate.roles.includes('acting'),
    );
    const inspection = this.#cards.get(selection.target.card_id);
    if (
      approval === undefined ||
      approval.re_confirmation_required === true ||
      inspection === undefined ||
      !inspection.signatureValid ||
      inspection.withdrawn ||
      inspection.integrityAlarm ||
      inspection.card.card_version !== approval.card_version ||
      inspection.card.model.requested_id !== approval.requested_id ||
      !verifyDigest(inspection.digest, approval.card_digest) ||
      !verifyDigest(selection.target.card_digest, approval.card_digest) ||
      selection.target.verifying_key_id !== inspection.keyId ||
      state.policy === undefined ||
      canonicalize(this.#systemUse.resolve(state, mandate, state.policy.policy_version, at)) !==
        canonicalize(selection.system_use_decision)
    ) {
      throw new ConversationTransportError('currentness', 'selected model governance is unavailable or changed');
    }
    return { mandate, approval, inspection, selection };
  }

  #caseEvents(state: WorldState) {
    return [...state.conversationEvents.values()].filter((event) => event.case_id === this.#caseId);
  }

  #assertCapacity(state: WorldState, additionalBytes: number): void {
    const events = this.#caseEvents(state);
    const bytes = events.reduce((total, event) => total + event.byte_length, 0);
    if (events.length >= MAX_CONVERSATION_EVENTS || bytes + additionalBytes > MAX_CONVERSATION_BYTES) {
      throw new ConversationTransportError('capacity', 'case conversation capacity is exhausted');
    }
  }

  async ingestMessage(
    requestInput: ConversationMessageIngressRequest,
    actor: TransactionActor,
    sessionIdInput: string,
  ): Promise<ConversationMessageIngressResult> {
    this.#requireOrchestrator(actor);
    const request = conversationMessageIngressRequest.parse(requestInput);
    const sessionId = id.parse(sessionIdInput);
    const byteLength = validateMessageText(request.text);
    const itemId = id.parse(this.#nextMessageItemId());
    const eventId = id.parse(this.#nextEventId());
    const completed = await this.#store.transactWithState<ConversationMessageIngressResult>(
      'conversation_message_ingress',
      actor,
      (state, at) => {
        this.#receipt(state, sessionId, at);
        const existing = this.#caseEvents(state).find(
          (event) => event.kind === 'message_ingress' && event.message_id === request.message_id,
        );
        if (existing !== undefined) {
          const entry = state.storeItems.get(existing.item_id);
          if (
            existing.kind !== 'message_ingress' ||
            existing.session_id !== sessionId ||
            existing.turn_id !== request.turn_id ||
            entry === undefined ||
            entry.item.text !== request.text ||
            !verifyDigest(existing.content_digest, contentDigest(this.#caseId, existing.item_id, request.text))
          ) {
            throw new ConversationTransportError('conflict', 'message id was already used with different bindings');
          }
          return {
            ops: [],
            result: conversationMessageIngressResult.parse({
              kind: 'conversation_message_ingress_result',
              message_id: existing.message_id,
              turn_id: existing.turn_id,
              message_item_id: existing.item_id,
              conversation_version: existing.conversation_version,
              message_digest: existing.content_digest,
              recorded_at: existing.recorded_at,
            }),
          };
        }
        const governance = this.#currentGovernance(state, at);
        const mandateClearance = governance.approval.data_classes.acting ?? [];
        const cardClearance = governance.inspection.card.declared_data_classes.acting ?? [];
        const effective = new Set(intersectClearances(mandateClearance, cardClearance));
        if (CASE_OFFICER_MESSAGE_TAGS.some((tag) => !effective.has(tag))) {
          throw new ConversationTransportError('currentness', 'selected acting lane cannot receive the fixed message profile');
        }
        if (
          [...state.modelCalls.values()].some(
            (call) => call.case_id === this.#caseId && call.state === 'open' && at < call.expires_at,
          )
        ) {
          throw new ConversationTransportError('conflict', 'an unexpired model call blocks message ingress');
        }
        this.#assertCapacity(state, byteLength);
        const version = (state.conversationVersionByCase.get(this.#caseId) ?? 0) + 1;
        const digest = contentDigest(this.#caseId, itemId, request.text);
        const entry = {
          world_id: state.worldId,
          case_id: this.#caseId,
          item: storeItem.parse({
            id: itemId,
            store: 'said',
            turn: request.turn_id,
            text: request.text,
            provenance: { derived_from: [], hops: [] },
            tags: [...CASE_OFFICER_MESSAGE_TAGS],
            origin_actor: 'officer',
          }),
        };
        const event = conversationIngressEvent.parse({
          kind: 'message_ingress',
          world_id: state.worldId,
          event_id: eventId,
          case_id: this.#caseId,
          message_id: request.message_id,
          turn_id: request.turn_id,
          item_id: itemId,
          conversation_version: version,
          content_digest: digest,
          byte_length: byteLength,
          recorded_at: at,
          session_id: sessionId,
          ingress_profile_id: CASE_OFFICER_MESSAGE_PROFILE_ID,
          ingress_profile_digest: CASE_OFFICER_MESSAGE_PROFILE_DIGEST,
        });
        return {
          ops: [
            ...conversationMutationInvalidationOps(state, this.#caseId, 'conversation-message-ingress', at),
            { op: 'store.put', entry },
            { op: 'conversation.event.append', event },
          ],
          result: conversationMessageIngressResult.parse({
            kind: 'conversation_message_ingress_result',
            message_id: request.message_id,
            turn_id: request.turn_id,
            message_item_id: itemId,
            conversation_version: version,
            message_digest: digest,
            recorded_at: at,
          }),
        };
      },
    );
    return completed.result;
  }

  assertIngressBinding(
    state: WorldState,
    at: string,
    bindingInput: ModelCallIngressBinding,
    turnId: string,
    sessionIdInput: string,
    projection: ReturnType<typeof projectConversation>,
  ): void {
    const binding = modelCallIngressBinding.parse(bindingInput);
    const receipt = this.#receipt(state, sessionIdInput, at);
    const event = this.#caseEvents(state).find(
      (candidate) => candidate.kind === 'message_ingress' && candidate.message_id === binding.message_id,
    );
    const entry = event === undefined ? undefined : state.storeItems.get(event.item_id);
    const projected = projection.items.find((item) => item.id === binding.message_item_id);
    if (
      event?.kind !== 'message_ingress' ||
      event.session_id !== receipt.session_id ||
      event.turn_id !== turnId ||
      event.item_id !== binding.message_item_id ||
      event.conversation_version !== binding.conversation_version ||
      !verifyDigest(event.content_digest, binding.message_digest) ||
      (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== binding.conversation_version ||
      entry === undefined ||
      projected === undefined ||
      canonicalize(projected) !== canonicalize(entry.item)
    ) {
      throw new ConversationTransportError('currentness', 'message ingress binding is unavailable or stale');
    }
  }

  prepareRelease(
    state: WorldState,
    at: string,
    call: ModelCallOpenRecord,
    decision: Extract<ModelOutputAdmission, { readonly disposition: 'admitted' }>,
  ): PreparedRelease {
    const ingress = call.ingress_binding;
    if (ingress === null) {
      throw new ConversationTransportError('invalid-scope', 'projection-only calls cannot receive output releases');
    }
    if (call.session_id === null) {
      throw new ConversationTransportError('invalid-scope', 'message-bound call has no session provenance');
    }
    this.#receipt(state, call.session_id, at);
    const governance = this.#currentGovernance(state, at);
    if (
      state.policy === undefined ||
      (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== ingress.conversation_version ||
      governance.selection.selection_id !== call.selection_id ||
      canonicalize(governance.selection.system_use_decision) !== canonicalize(call.system_use_decision)
    ) {
      throw new ConversationTransportError('currentness', 'message-bound call is no longer current');
    }
    const releaseId = id.parse(this.#nextReleaseId());
    const expiresAt = timestamp.parse(new Date(Date.parse(at) + this.#releaseTtlMs).toISOString());
    const release = outputReleaseRecord.parse({
      world_id: state.worldId,
      release_id: releaseId,
      authorization_boot_id: this.#authorizationBootId,
      call_id: call.call_id,
      case_id: this.#caseId,
      turn_id: call.turn_id,
      session_id: call.session_id,
      message_id: ingress.message_id,
      message_item_id: ingress.message_item_id,
      conversation_version: ingress.conversation_version,
      selection_id: call.selection_id,
      mandate_id: call.mandate_id,
      mandate_version: call.mandate_version,
      card_id: call.card_id,
      card_version: call.card_version,
      card_digest: governance.inspection.digest,
      verifying_key_id: governance.inspection.keyId,
      requested_id: call.requested_id,
      served_id: decision.served_id,
      system_use_decision: call.system_use_decision,
      policy_version: state.policy.policy_version,
      policy_content_digest: state.policy.policy_content_digest,
      evaluator_build_id: state.policy.evaluator_build_id,
      projection_item_ids: call.projection_item_ids,
      projection_digest: call.projection_digest,
      output_digest: decision.output_digest,
      derived_tags: decision.derived_tags,
      issued_at: at,
      expires_at: expiresAt,
      state: 'issued',
      state_changed_at: at,
      invalidation_reason: null,
      consumption_result: null,
    });
    return {
      op: { op: 'output_release.issue', release },
      reference: outputReleaseReference.parse({ release_id: releaseId, call_id: call.call_id, expires_at: expiresAt }),
    };
  }

  #releaseIsCurrent(state: WorldState, release: OutputReleaseRecord, at: string): boolean {
    try {
      if (
        release.authorization_boot_id !== this.#authorizationBootId ||
        release.case_id !== this.#caseId ||
        at >= release.expires_at ||
        (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== release.conversation_version ||
        state.policy === undefined ||
        state.policy.policy_version !== release.policy_version ||
        !verifyDigest(state.policy.policy_content_digest, release.policy_content_digest) ||
        state.policy.evaluator_build_id !== release.evaluator_build_id ||
        !this.#systemUse.isReferenceCurrent(state, release.system_use_decision, at)
      ) {
        return false;
      }
      const governance = this.#currentGovernance(state, at);
      const call = state.modelCalls.get(release.call_id);
      const receipt = state.caseSessionProvenance.get(release.session_id);
      const messageEvent = [...state.conversationEvents.values()].find(
        (event) => event.kind === 'message_ingress' && event.message_id === release.message_id,
      );
      if (
        call === undefined ||
        call.state !== 'terminal' ||
        call.outcome !== 'admitted' ||
        call.ingress_binding === null ||
        receipt === undefined ||
        receipt.state !== 'active' ||
        receipt.authorization_boot_id !== this.#authorizationBootId ||
        receipt.case_id !== this.#caseId ||
        at >= receipt.expires_at ||
        governance.selection.selection_id !== release.selection_id ||
        governance.mandate.mandate_id !== release.mandate_id ||
        governance.mandate.version !== release.mandate_version ||
        governance.inspection.card.card_id !== release.card_id ||
        governance.inspection.card.card_version !== release.card_version ||
        !verifyDigest(governance.inspection.digest, release.card_digest) ||
        governance.inspection.keyId !== release.verifying_key_id ||
        governance.approval.requested_id !== release.requested_id ||
        call.served_id !== release.served_id ||
        call.output_digest !== release.output_digest ||
        call.ingress_binding.message_id !== release.message_id ||
        call.ingress_binding.message_item_id !== release.message_item_id ||
        call.ingress_binding.conversation_version !== release.conversation_version ||
        messageEvent?.kind !== 'message_ingress' ||
        messageEvent.session_id !== release.session_id ||
        messageEvent.item_id !== release.message_item_id ||
        !verifyDigest(messageEvent.content_digest, call.ingress_binding.message_digest) ||
        canonicalize(call.projection_item_ids) !== canonicalize(release.projection_item_ids) ||
        !verifyDigest(call.projection_digest, release.projection_digest) ||
        canonicalize(call.system_use_decision) !== canonicalize(release.system_use_decision)
      ) {
        return false;
      }
      const projection = projectConversation({
        worldId: state.worldId,
        caseId: this.#caseId,
        provider: governance.approval.card_id,
        role: 'acting',
        mandateClearances: governance.approval.data_classes.acting ?? [],
        cardClearances: governance.inspection.card.declared_data_classes.acting ?? [],
        entries: [...state.storeItems.values()],
      });
      return (
        verifyDigest(digestFor('conversation-projection', projection), release.projection_digest) &&
        canonicalize(projection.items.map((item) => item.id)) === canonicalize(release.projection_item_ids) &&
        canonicalize(unionRestrictionTags(projection.items)) === canonicalize(release.derived_tags)
      );
    } catch {
      return false;
    }
  }

  async consumeRelease(
    releaseIdInput: string,
    content: string,
    actor: TransactionActor,
    sessionIdInput: string,
  ): Promise<OutputReleaseConsumeResult> {
    this.#requireOrchestrator(actor);
    const releaseId = id.parse(releaseIdInput);
    const sessionId = id.parse(sessionIdInput);
    const eventId = id.parse(this.#nextEventId());
    const itemId = id.parse(this.#nextMessageItemId());
    const completed = await this.#store.transactWithState<ConsumptionFailure | ConsumptionSuccess>(
      'output_release_consume',
      actor,
      (state, at) => {
        const release = state.outputReleases.get(releaseId);
        if (release === undefined || release.case_id !== this.#caseId) {
          throw new ConversationTransportError('unavailable', 'output release is unavailable');
        }
        this.#receipt(state, sessionId, at);
        if (release.session_id !== sessionId) {
          throw new ConversationTransportError('forbidden', 'output release session does not match');
        }
        let request;
        try {
          request = modelOutputAdmissionRequest.parse({
            turn_id: release.turn_id,
            selection_id: release.selection_id,
            mandate_id: release.mandate_id,
            mandate_version: release.mandate_version,
            card_id: release.card_id,
            card_version: release.card_version,
            requested_id: release.requested_id,
            served_id: release.served_id,
            projection_digest: release.projection_digest,
            content,
          });
        } catch {
          if (release.state !== 'issued') {
            throw new ConversationTransportError('unavailable', 'output release is unavailable');
          }
          return {
            ops: [{ op: 'output_release.invalidate', release_id: releaseId, reason: 'output-content-invalid', changed_at: at }],
            result: { kind: 'failure', message: 'output release content is invalid' },
          };
        }
        const digestMatches = verifyDigest(digestModelOutput(request, this.#caseId), release.output_digest);
        if (release.state === 'consumed') {
          const result = release.consumption_result;
          const event = result === null ? undefined : state.conversationEvents.get(result.event_id);
          const entry = result === null ? undefined : state.storeItems.get(result.item_id);
          if (
            !digestMatches ||
            result === null ||
            event?.kind !== 'model_output_ingress' ||
            entry === undefined ||
            entry.item.text !== content
          ) {
            throw new ConversationTransportError('conflict', 'consumed release replay does not match recorded content');
          }
          return {
            ops: [],
            result: {
              kind: 'success',
              result: outputReleaseConsumeResult.parse({
                kind: 'output_release_consumption_result',
                release_id: release.release_id,
                state: 'consumed',
                ...result,
              }),
            },
          };
        }
        if (release.state !== 'issued') {
          throw new ConversationTransportError('unavailable', 'output release is unavailable');
        }
        if (at >= release.expires_at) {
          return {
            ops: [
              {
                op: 'output_release.expire',
                release_id: releaseId,
                authorization_boot_id: this.#authorizationBootId,
                changed_at: at,
              },
            ],
            result: { kind: 'failure', message: 'output release expired' },
          };
        }
        if (!digestMatches || !this.#releaseIsCurrent(state, release, at)) {
          return {
            ops: [{ op: 'output_release.invalidate', release_id: releaseId, reason: 'release-currentness-failed', changed_at: at }],
            result: { kind: 'failure', message: 'output release currentness failed' },
          };
        }
        const byteLength = Buffer.byteLength(content, 'utf8');
        try {
          this.#assertCapacity(state, byteLength);
        } catch (error) {
          if (!(error instanceof ConversationTransportError) || error.code !== 'capacity') throw error;
          return {
            ops: [{ op: 'output_release.invalidate', release_id: releaseId, reason: 'conversation-capacity', changed_at: at }],
            result: { kind: 'failure', message: 'case conversation capacity is exhausted' },
          };
        }
        const version = (state.conversationVersionByCase.get(this.#caseId) ?? 0) + 1;
        const digest = contentDigest(this.#caseId, itemId, content);
        const entry = {
          world_id: state.worldId,
          case_id: this.#caseId,
          item: storeItem.parse({
            id: itemId,
            store: 'inferred',
            turn: release.turn_id,
            text: content,
            provenance: {
              derived_from: release.projection_item_ids,
              hops: [{ requested: release.requested_id, served: release.served_id }],
            },
            tags: release.derived_tags,
          }),
        };
        const event = conversationIngressEvent.parse({
          kind: 'model_output_ingress',
          world_id: state.worldId,
          event_id: eventId,
          case_id: this.#caseId,
          message_id: release.message_id,
          turn_id: release.turn_id,
          item_id: itemId,
          conversation_version: version,
          content_digest: digest,
          byte_length: byteLength,
          recorded_at: at,
          release_id: release.release_id,
          requested_id: release.requested_id,
          served_id: release.served_id,
        });
        const result = {
          event_id: eventId,
          item_id: itemId,
          conversation_version: version,
          recorded_at: at,
        };
        return {
          ops: [
            { op: 'store.put', entry },
            { op: 'conversation.event.append', event },
            { op: 'output_release.consume', release_id: release.release_id, result },
            ...conversationMutationInvalidationOps(
              state,
              this.#caseId,
              'conversation-model-output-ingress',
              at,
              release.release_id,
            ),
          ],
          result: {
            kind: 'success',
            result: outputReleaseConsumeResult.parse({
              kind: 'output_release_consumption_result',
              release_id: release.release_id,
              state: 'consumed',
              ...result,
            }),
          },
        };
      },
    );
    if (completed.result.kind === 'failure') {
      throw new ConversationTransportError('currentness', completed.result.message);
    }
    return completed.result.result;
  }

  releaseStatus(
    releaseIdInput: string,
    actor: TransactionActor,
    sessionIdInput: string,
  ): OutputReleaseStatusProjection {
    this.#requireOrchestrator(actor);
    const state = this.#store.snapshot();
    const sessionId = id.parse(sessionIdInput);
    this.#receipt(state, sessionId, timestamp.parse(this.#now()));
    const release = state.outputReleases.get(id.parse(releaseIdInput));
    if (release === undefined || release.case_id !== this.#caseId || release.session_id !== sessionId) {
      throw new ConversationTransportError('unavailable', 'output release is unavailable');
    }
    return outputReleaseStatusProjection.parse({
      kind: 'output_release_status',
      release_id: release.release_id,
      call_id: release.call_id,
      state: release.state,
      issued_at: release.issued_at,
      expires_at: release.expires_at,
      state_changed_at: release.state_changed_at,
      consumption_result: release.consumption_result,
    });
  }

  releaseConsumptionEvidence(releaseIdInput: string, result: OutputReleaseConsumeResult) {
    const release = this.#store.snapshot().outputReleases.get(id.parse(releaseIdInput));
    if (release === undefined || release.state !== 'consumed' || release.consumption_result === null) {
      throw new ConversationTransportError('unavailable', 'consumed output release evidence is unavailable');
    }
    return {
      kind: 'output_release_consumed' as const,
      release_id: release.release_id,
      call_id: release.call_id,
      case_id: release.case_id,
      turn_id: release.turn_id,
      event_id: result.event_id,
      item_id: result.item_id,
      conversation_version: result.conversation_version,
      state: 'consumed' as const,
      recorded_at: result.recorded_at,
    };
  }

  conversation(actor: TransactionActor, sessionIdInput: string): ConversationProcessProjection {
    this.#requireOrchestrator(actor);
    const state = this.#store.snapshot();
    this.#receipt(state, id.parse(sessionIdInput), timestamp.parse(this.#now()));
    const events: ConversationProcessEvent[] = [];
    for (const event of this.#caseEvents(state)) {
      const entry = state.storeItems.get(event.item_id);
      if (entry === undefined || entry.case_id !== this.#caseId) continue;
      events.push(
        event.kind === 'message_ingress'
          ? {
              speaker: 'case_officer',
              message_id: event.message_id,
              turn_id: event.turn_id,
              text: entry.item.text,
              recorded_at: event.recorded_at,
            }
          : {
              speaker: 'model',
              message_id: event.message_id,
              turn_id: event.turn_id,
              text: entry.item.text,
              recorded_at: event.recorded_at,
              requested_id: event.requested_id,
              served_id: event.served_id,
              classification: 'inferred-unconfirmed',
            },
      );
    }
    if (events.length > MAX_CONVERSATION_EVENTS || events.reduce((sum, event) => sum + Buffer.byteLength(event.text, 'utf8'), 0) > MAX_CONVERSATION_BYTES) {
      throw new ConversationTransportError('capacity', 'recorded conversation exceeds the process projection bound');
    }
    return conversationProcessProjection.parse({
      case_id: this.#caseId,
      conversation_version: state.conversationVersionByCase.get(this.#caseId) ?? 0,
      events,
    });
  }

  async expireReleases(actor: TransactionActor): Promise<number> {
    if (actor.credential !== 'proc:authz') {
      throw new ConversationTransportError('forbidden', 'only authorization may expire output releases');
    }
    const completed = await this.#store.transactWithState<number>('output_release_expire', actor, (state, at) => {
      const ops: WalOp[] = [...state.outputReleases.values()]
        .filter(
          (release) =>
            release.state === 'issued' &&
            (release.authorization_boot_id !== this.#authorizationBootId || at >= release.expires_at),
        )
        .map((release) => ({
          op: 'output_release.expire',
          release_id: release.release_id,
          authorization_boot_id: this.#authorizationBootId,
          changed_at: at,
        }));
      return { ops, result: ops.length };
    });
    return completed.result;
  }
}
