// SPDX-License-Identifier: MIT
/** M5.4 containment plus M5.5 durable model-call lifecycle coordinator. */
import {
  MAX_MODEL_OUTPUT_CHARS,
  canonicalize,
  cardSlug,
  digestFor,
  digestModelOutput,
  id,
  integer,
  modelId,
  modelCallAdmission,
  modelCallFailureRequest,
  modelCallStart,
  currentModelSelectionProjection,
  modelSelectionCheckProjection,
  modelSelectionProjection,
  modelSelectionTarget,
  modelOutputAdmission,
  modelOutputAdmissionRequest,
  modelCallIngressBinding,
  conversationMessageIngressResult,
  outputReleaseConsumeResult,
  outputReleaseStatusProjection,
  sortedRestrictionTags,
  verifyDigest,
  worldId,
  type ConversationProjection,
  type ModelCallAdmission,
  type ModelCallFailedRecord,
  type ModelCallFailureReason,
  type ModelCallFailureRequest,
  type ModelCallStart,
  type CurrentModelSelectionProjection,
  type ModelSelectionCheckProjection,
  type ModelSelectionCheckRequest,
  type ModelSelectionProjection,
  type ModelSelectionRequest,
  type ModelSelectionTarget,
  type ModelOutputAdmission,
  type ModelOutputAdmissionRequest,
  type ConversationMessageIngressRequest,
  type ConversationMessageIngressResult,
  type ModelCallIngressBinding,
  type OutputReleaseConsumeResult,
  type OutputReleaseStatusProjection,
} from 'gate-core';
import {
  ModelAdapterError,
  type ActingRequest,
  type ActingResponse,
  type ModelLane,
  type OpenAiCompatibleAdapter,
} from 'model-adapters';
import { z } from 'zod';

import { RuntimeDependencyError } from './runtimeHttpClients.js';

const modelTurnInput = z
  .object({
    turnId: id,
    selectionId: id,
    cardId: cardSlug,
    cardVersion: integer.min(1),
    requestedId: modelId,
    maxOutputTokens: integer.min(1).max(8_192),
  })
  .strict();

const messageBoundModelTurnInput = modelTurnInput
  .extend({
    messageId: id,
    text: z.string(),
  })
  .strict();

const quarantinedModelOutputRef = z
  .object({
    kind: z.literal('quarantined_model_output'),
    release_state: z.enum(['sealed-no-release-path', 'sealed-release-pending']),
    call_id: id,
    case_id: id,
    turn_id: id,
    selection_id: id,
    card_id: cardSlug,
    card_version: integer.min(1),
    requested_id: modelId,
    served_id: modelId,
    projection_digest: z.string().regex(/^[0-9a-f]{64}$/),
    output_digest: z.string().regex(/^[0-9a-f]{64}$/),
    derived_tags: sortedRestrictionTags,
  })
  .strict();

const actingResponse = z
  .object({
    lane: z.enum(['publicai', 'openai']),
    requestedId: modelId,
    servedId: modelId,
    content: z.string().min(1).max(MAX_MODEL_OUTPUT_CHARS),
    toolCalls: z.array(z.unknown()).length(0),
  })
  .strict();

type AdmittedOutput = Extract<ModelOutputAdmission, { disposition: 'admitted' }>;
type WithheldOutput = Extract<ModelOutputAdmission, { disposition: 'withheld' }>;

export type ModelTurnInput = z.infer<typeof modelTurnInput>;
export type QuarantinedModelOutputRef = z.infer<typeof quarantinedModelOutputRef>;

export type ModelTurnOutcome =
  | {
      readonly disposition: 'quarantined';
      readonly admission: AdmittedOutput;
      readonly quarantine: QuarantinedModelOutputRef;
    }
  | {
      readonly disposition: 'withheld';
      readonly admission: WithheldOutput;
    }
  | {
      readonly disposition: 'released';
      readonly admission: AdmittedOutput;
      readonly ingestion: OutputReleaseConsumeResult;
    };

export type ModelTurnErrorCode =
  | 'invalid-configuration'
  | 'lane-unconfigured'
  | 'lane-halted'
  | 'lane-busy'
  | 'turn-replay'
  | 'authorization-refused'
  | 'provider-failure'
  | 'provider-protocol'
  | 'quarantine-capacity'
  | 'admission-binding-invalid';

export interface ModelTurnCallerClaim {
  readonly role: 'case_officer';
  readonly session_id: string;
}

export interface ModelTurnRunContext {
  readonly onBehalfOf?: ModelTurnCallerClaim;
  readonly onProviderAttempt?: () => void;
}

export type MessageBoundModelTurnInput = z.infer<typeof messageBoundModelTurnInput>;

export class ModelTurnError extends Error {
  constructor(
    readonly code: ModelTurnErrorCode,
    readonly providerDisclosure: 'none' | 'possible' | 'confirmed' = 'none',
    readonly servedId: string | null = null,
  ) {
    super(code);
    this.name = 'ModelTurnError';
  }
}

function isSystemUseInvalidation(error: unknown): boolean {
  if (error instanceof RuntimeDependencyError) return error.responseCode === 'system-use-unavailable';
  return (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    (error as { readonly code?: unknown }).code === 'system-use-unavailable'
  );
}

interface ActingAdapter {
  readonly lane: ModelLane;
  readonly requestedId: string;
  act(request: ActingRequest): Promise<ActingResponse>;
}

export interface ModelTurnLaneConfig {
  readonly lane: ModelLane;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly requestedId: string;
  readonly adapter: Pick<OpenAiCompatibleAdapter, 'act' | 'lane' | 'requestedId'> | ActingAdapter;
}

export interface ModelTurnAuthorizationClient {
  currentModelSelection(worldIdInput: string, caseIdInput: string): Promise<CurrentModelSelectionProjection>;
  checkModelSelection(
    worldIdInput: string,
    caseIdInput: string,
    input: ModelSelectionCheckRequest,
  ): Promise<ModelSelectionCheckProjection>;
  selectModel(
    worldIdInput: string,
    caseIdInput: string,
    input: ModelSelectionRequest,
  ): Promise<ModelSelectionProjection>;
  beginModelCall(input: {
    readonly worldId: string;
    readonly turnId: string;
    readonly selectionId: string;
  }, onBehalfOf?: ModelTurnCallerClaim): Promise<ModelCallStart>;
  admitModelOutput(
    worldIdInput: string,
    callIdInput: string,
    input: ModelOutputAdmissionRequest,
    onBehalfOf?: ModelTurnCallerClaim,
  ): Promise<ModelCallAdmission>;
  failModelCall(
    worldIdInput: string,
    input: ModelCallFailureRequest,
    onBehalfOf?: ModelTurnCallerClaim,
  ): Promise<ModelCallFailedRecord>;
  ingestConversationMessage?(
    worldIdInput: string,
    caseIdInput: string,
    input: ConversationMessageIngressRequest,
    onBehalfOf: ModelTurnCallerClaim,
  ): Promise<ConversationMessageIngressResult>;
  consumeOutputRelease?(
    worldIdInput: string,
    releaseIdInput: string,
    content: string,
    onBehalfOf: ModelTurnCallerClaim,
  ): Promise<OutputReleaseConsumeResult>;
  outputReleaseStatus?(
    worldIdInput: string,
    releaseIdInput: string,
    onBehalfOf: ModelTurnCallerClaim,
  ): Promise<OutputReleaseStatusProjection>;
}

export interface ModelTurnCoordinatorOptions {
  readonly worldId: string;
  readonly caseId: string;
  readonly authorization: ModelTurnAuthorizationClient;
  readonly lanes: readonly ModelTurnLaneConfig[];
  readonly quarantine?: ModelOutputQuarantine;
}

interface BoundLane {
  readonly lane: ModelLane;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly requestedId: string;
  readonly adapter: ActingAdapter;
}

interface HeldOutput {
  readonly ref: QuarantinedModelOutputRef;
  readonly releaseId: string | null;
  readonly bytes: Buffer;
}

type QuarantineSealer = (
  callId: string,
  request: ModelOutputAdmissionRequest,
  decision: AdmittedOutput,
  caseId: string,
  releaseId: string | null,
) => QuarantinedModelOutputRef;

type QuarantineConsumer = <T>(
  turnId: string,
  releaseId: string,
  sink: (content: string) => Promise<T>,
) => Promise<T>;

/** Module-private capability: importers can inspect or destroy quarantine entries but cannot create one. */
const quarantineSealers = new WeakMap<ModelOutputQuarantine, QuarantineSealer>();
const quarantineConsumers = new WeakMap<ModelOutputQuarantine, QuarantineConsumer>();

function laneKey(cardIdInput: string, cardVersionInput: number, requestedIdInput: string): string {
  return `${cardSlug.parse(cardIdInput)}@${integer.min(1).parse(cardVersionInput)}\n${modelId.parse(requestedIdInput)}`;
}

function bindingMatches(
  decision: ModelOutputAdmission,
  request: ModelOutputAdmissionRequest,
  caseIdInput: string,
): boolean {
  return (
    decision.case_id === caseIdInput &&
    decision.turn_id === request.turn_id &&
    decision.selection_id === request.selection_id &&
    decision.mandate_id === request.mandate_id &&
    decision.mandate_version === request.mandate_version &&
    decision.card_id === request.card_id &&
    decision.card_version === request.card_version &&
    decision.requested_id === request.requested_id &&
    decision.served_id === request.served_id &&
    verifyDigest(decision.projection_digest, request.projection_digest) &&
    verifyDigest(decision.output_digest, digestModelOutput(request, caseIdInput))
  );
}

function providerFailureEvidence(error: unknown): {
  readonly failureReason: ModelCallFailureReason;
  readonly providerDisclosure: 'possible' | 'confirmed';
} {
  if (error instanceof ModelAdapterError) {
    if (error.code === 'timeout') return { failureReason: 'provider-timeout', providerDisclosure: 'possible' };
    if (error.code === 'malformed-response') {
      return { failureReason: 'malformed-response', providerDisclosure: 'confirmed' };
    }
    return {
      failureReason: 'provider-unavailable',
      providerDisclosure: error.httpStatus === undefined ? 'possible' : 'confirmed',
    };
  }
  return { failureReason: 'provider-unavailable', providerDisclosure: 'possible' };
}

function protocolFailureEvidence(response: unknown): {
  readonly failureReason: ModelCallFailureReason;
  readonly servedId: string | null;
} {
  try {
    if (typeof response !== 'object' || response === null) {
      return { failureReason: 'malformed-response', servedId: null };
    }
    const served = modelId.safeParse(Reflect.get(response, 'servedId'));
    const toolCalls = Reflect.get(response, 'toolCalls');
    return {
      failureReason:
        served.success && Array.isArray(toolCalls) && toolCalls.length > 0
          ? 'tool-calls-refused'
          : 'malformed-response',
      servedId: served.success ? served.data : null,
    };
  } catch {
    return { failureReason: 'malformed-response', servedId: null };
  }
}

/**
 * Process-private holding area. Importers receive metadata and destruction only: no exported
 * method can seal, read, or release held bytes. M5.10's distinct module-private consumer removes
 * a release-bound entry before passing one copy directly to authorization transport. This is
 * structural confinement, not cryptographic proof or safety clearance.
 */
export class ModelOutputQuarantine {
  readonly #held = new Map<string, HeldOutput>();
  readonly #seen = new Set<string>();
  readonly #maxEntries: number;
  readonly #maxHeldBytes: number;
  #heldBytes = 0;

  constructor(options: { readonly maxEntries?: number; readonly maxHeldBytes?: number } = {}) {
    this.#maxEntries = integer.min(1).parse(options.maxEntries ?? 8);
    this.#maxHeldBytes = integer.min(1).parse(options.maxHeldBytes ?? 1_048_576);
    quarantineSealers.set(this, (callId, request, decision, caseId, releaseId) =>
      this.#seal(callId, request, decision, caseId, releaseId),
    );
    quarantineConsumers.set(this, (turnId, releaseId, sink) => this.#consume(turnId, releaseId, sink));
  }

  #seal(
    callIdInput: string,
    requestInput: ModelOutputAdmissionRequest,
    decisionInput: AdmittedOutput,
    caseIdInput: string,
    releaseIdInput: string | null,
  ): QuarantinedModelOutputRef {
    const request = modelOutputAdmissionRequest.parse(requestInput);
    const decision = modelOutputAdmission.parse(decisionInput);
    const callId = id.parse(callIdInput);
    const caseId = id.parse(caseIdInput);
    const releaseId = releaseIdInput === null ? null : id.parse(releaseIdInput);
    if (decision.disposition !== 'admitted' || !bindingMatches(decision, request, caseId)) {
      throw new ModelTurnError('admission-binding-invalid');
    }
    if (this.#seen.has(request.turn_id)) throw new ModelTurnError('turn-replay');
    const ref = quarantinedModelOutputRef.parse({
      kind: 'quarantined_model_output',
      release_state: releaseId === null ? 'sealed-no-release-path' : 'sealed-release-pending',
      call_id: callId,
      case_id: caseId,
      turn_id: request.turn_id,
      selection_id: request.selection_id,
      card_id: request.card_id,
      card_version: request.card_version,
      requested_id: request.requested_id,
      served_id: request.served_id,
      projection_digest: request.projection_digest,
      output_digest: decision.output_digest,
      derived_tags: decision.derived_tags,
    });
    const bytes = Buffer.from(request.content, 'utf8');
    if (this.#held.size >= this.#maxEntries || this.#heldBytes + bytes.byteLength > this.#maxHeldBytes) {
      bytes.fill(0);
      throw new ModelTurnError('quarantine-capacity');
    }
    this.#seen.add(request.turn_id);
    this.#held.set(request.turn_id, { ref, releaseId, bytes });
    this.#heldBytes += bytes.byteLength;
    return ref;
  }

  async #consume<T>(turnIdInput: string, releaseIdInput: string, sink: (content: string) => Promise<T>): Promise<T> {
    const turnId = id.parse(turnIdInput);
    const releaseId = id.parse(releaseIdInput);
    const held = this.#held.get(turnId);
    if (held === undefined || held.releaseId !== releaseId || held.ref.release_state !== 'sealed-release-pending') {
      if (held !== undefined) this.destroy(turnId);
      throw new ModelTurnError('admission-binding-invalid');
    }
    // The local capability is consumed before the first transport byte leaves this process.
    this.#held.delete(turnId);
    this.#heldBytes -= held.bytes.byteLength;
    try {
      return await sink(held.bytes.toString('utf8'));
    } finally {
      held.bytes.fill(0);
    }
  }

  metadata(turnIdInput: string): QuarantinedModelOutputRef | null {
    const held = this.#held.get(id.parse(turnIdInput));
    return held === undefined ? null : { ...held.ref, derived_tags: [...held.ref.derived_tags] };
  }

  has(turnIdInput: string): boolean {
    return this.#held.has(id.parse(turnIdInput));
  }

  get size(): number {
    return this.#held.size;
  }

  destroy(turnIdInput: string): boolean {
    const turnId = id.parse(turnIdInput);
    const held = this.#held.get(turnId);
    if (held === undefined) return false;
    this.#heldBytes -= held.bytes.byteLength;
    held.bytes.fill(0);
    this.#held.delete(turnId);
    return true;
  }

  destroySelection(selectionIdInput: string): number {
    const selectionId = id.parse(selectionIdInput);
    const turnIds = [...this.#held.values()]
      .filter((held) => held.ref.selection_id === selectionId)
      .map((held) => held.ref.turn_id);
    for (const turnId of turnIds) this.destroy(turnId);
    return turnIds.length;
  }

  clear(): void {
    for (const held of this.#held.values()) held.bytes.fill(0);
    this.#held.clear();
    this.#heldBytes = 0;
  }
}

function sealQuarantinedOutput(
  quarantine: ModelOutputQuarantine,
  callId: string,
  request: ModelOutputAdmissionRequest,
  decision: AdmittedOutput,
  caseId: string,
  releaseId: string | null,
): QuarantinedModelOutputRef {
  const seal = quarantineSealers.get(quarantine);
  if (seal === undefined) throw new ModelTurnError('invalid-configuration');
  return seal(callId, request, decision, caseId, releaseId);
}

async function consumeQuarantinedOutput<T>(
  quarantine: ModelOutputQuarantine,
  turnId: string,
  releaseId: string,
  sink: (content: string) => Promise<T>,
): Promise<T> {
  const consume = quarantineConsumers.get(quarantine);
  if (consume === undefined) throw new ModelTurnError('invalid-configuration');
  return consume(turnId, releaseId, sink);
}

function projectionPrompt(projection: ConversationProjection): ActingRequest['messages'] {
  return [
    {
      role: 'system',
      content:
        'Use only the authorization-projected synthetic case items below. Return text only; do not call tools. The model never authorizes an action.',
    },
    {
      role: 'user',
      content: canonicalize({ schema: 'ai-charter-runtime/model-turn-input@1', projection }),
    },
  ];
}

/**
 * Fetches only an authorization-owned projection, calls one configured lane, and sends
 * the result back to authorization. Even an admitted result remains sealed and unreadable.
 */
export class ModelTurnCoordinator {
  readonly #worldId: string;
  readonly #caseId: string;
  readonly #authorization: ModelTurnAuthorizationClient;
  readonly #lanes = new Map<string, BoundLane>();
  readonly #quarantine: ModelOutputQuarantine;
  readonly #seenTurns = new Set<string>();
  readonly #haltedLanes = new Set<string>();
  readonly #busyLanes = new Set<string>();

  constructor(options: ModelTurnCoordinatorOptions) {
    this.#worldId = worldId.parse(options.worldId);
    this.#caseId = id.parse(options.caseId);
    this.#authorization = options.authorization;
    this.#quarantine = options.quarantine ?? new ModelOutputQuarantine();
    for (const input of options.lanes) {
      const lane = z.enum(['publicai', 'openai']).parse(input.lane);
      const cardId = cardSlug.parse(input.cardId);
      const cardVersion = integer.min(1).parse(input.cardVersion);
      const requestedId = modelId.parse(input.requestedId);
      const key = laneKey(cardId, cardVersion, requestedId);
      if (
        this.#lanes.has(key) ||
        input.adapter.lane !== lane ||
        input.adapter.requestedId !== requestedId
      ) {
        throw new ModelTurnError('invalid-configuration');
      }
      this.#lanes.set(key, { lane, cardId, cardVersion, requestedId, adapter: input.adapter });
    }
  }

  get quarantine(): ModelOutputQuarantine {
    return this.#quarantine;
  }

  isLaneHalted(cardIdInput: string, cardVersionInput: number, requestedIdInput: string): boolean {
    return this.#haltedLanes.has(laneKey(cardIdInput, cardVersionInput, requestedIdInput));
  }

  hasConfiguredLane(cardIdInput: string, cardVersionInput: number, requestedIdInput: string): boolean {
    return this.#lanes.has(laneKey(cardIdInput, cardVersionInput, requestedIdInput));
  }

  async currentSelection(): Promise<CurrentModelSelectionProjection> {
    return currentModelSelectionProjection.parse(
      await this.#authorization.currentModelSelection(this.#worldId, this.#caseId),
    );
  }

  async select(input: {
    readonly expectedCurrentSelectionId: string | null;
    readonly target: ModelSelectionTarget;
  }): Promise<ModelSelectionProjection> {
    const expectedCurrentSelectionId =
      input.expectedCurrentSelectionId === null ? null : id.parse(input.expectedCurrentSelectionId);
    const target = modelSelectionTarget.parse(input.target);
    const checked = modelSelectionCheckProjection.parse(
      await this.#authorization.checkModelSelection(this.#worldId, this.#caseId, {
        expected_current_selection_id: expectedCurrentSelectionId,
        target,
      }),
    );
    if (
      checked.check.expected_current_selection_id !== expectedCurrentSelectionId ||
      canonicalize({
        card_id: checked.check.target.card_id,
        card_version: checked.check.target.card_version,
        requested_id: checked.check.target.requested_id,
      }) !== canonicalize(target) ||
      checked.evidence.approval.card_id !== target.card_id ||
      checked.evidence.approval.card_version !== target.card_version ||
      checked.evidence.approval.requested_id !== target.requested_id ||
      checked.evidence.current_card_digest !== checked.check.target.card_digest ||
      checked.evidence.verifying_key_id !== checked.check.target.verifying_key_id
    ) {
      throw new ModelTurnError('authorization-refused');
    }
    const selected = modelSelectionProjection.parse(
      await this.#authorization.selectModel(this.#worldId, this.#caseId, {
        check_id: checked.check.check_id,
        expected_current_selection_id: expectedCurrentSelectionId,
      }),
    );
    if (
      selected.selection.predecessor_selection_id !== expectedCurrentSelectionId ||
      selected.selection.check_id !== checked.check.check_id ||
      selected.selection.case_id !== this.#caseId ||
      selected.selection.world_id !== this.#worldId ||
      canonicalize(selected.selection.target) !== canonicalize(checked.check.target)
    ) {
      throw new ModelTurnError('authorization-refused');
    }
    if (expectedCurrentSelectionId !== null) this.#quarantine.destroySelection(expectedCurrentSelectionId);
    return selected;
  }

  async run(inputValue: ModelTurnInput, context: ModelTurnRunContext = {}): Promise<ModelTurnOutcome> {
    return this.#run(inputValue, context, null);
  }

  async runMessage(
    inputValue: MessageBoundModelTurnInput,
    context: ModelTurnRunContext,
  ): Promise<ModelTurnOutcome> {
    const { messageId, text, ...input } = messageBoundModelTurnInput.parse(inputValue);
    const claim = context.onBehalfOf;
    if (
      claim === undefined ||
      this.#authorization.ingestConversationMessage === undefined ||
      this.#authorization.consumeOutputRelease === undefined ||
      this.#authorization.outputReleaseStatus === undefined
    ) {
      throw new ModelTurnError('invalid-configuration');
    }
    let ingress: ConversationMessageIngressResult;
    try {
      ingress = conversationMessageIngressResult.parse(
        await this.#authorization.ingestConversationMessage(
          this.#worldId,
          this.#caseId,
          { message_id: messageId, turn_id: input.turnId, text },
          claim,
        ),
      );
    } catch {
      throw new ModelTurnError('authorization-refused');
    }
    if (ingress.message_id !== messageId || ingress.turn_id !== input.turnId) {
      throw new ModelTurnError('authorization-refused');
    }
    return this.#run(
      input,
      context,
      modelCallIngressBinding.parse({
        message_id: ingress.message_id,
        message_item_id: ingress.message_item_id,
        conversation_version: ingress.conversation_version,
        message_digest: ingress.message_digest,
      }),
    );
  }

  async #run(
    inputValue: ModelTurnInput,
    context: ModelTurnRunContext,
    ingressBinding: ModelCallIngressBinding | null,
  ): Promise<ModelTurnOutcome> {
    const input = modelTurnInput.parse(inputValue);
    const key = laneKey(input.cardId, input.cardVersion, input.requestedId);
    const lane = this.#lanes.get(key);
    if (lane === undefined) throw new ModelTurnError('lane-unconfigured');
    if (this.#haltedLanes.has(key)) throw new ModelTurnError('lane-halted');
    if (this.#busyLanes.has(key)) throw new ModelTurnError('lane-busy');
    this.#busyLanes.add(key);
    try {
      if (this.#seenTurns.has(input.turnId)) throw new ModelTurnError('turn-replay');
      this.#seenTurns.add(input.turnId);

      const halt = (
        code: ModelTurnErrorCode,
        providerDisclosure: 'none' | 'possible' | 'confirmed' = 'none',
        servedId: string | null = null,
      ): never => {
        this.#quarantine.destroy(input.turnId);
        this.#haltedLanes.add(key);
        throw new ModelTurnError(code, providerDisclosure, servedId);
      };

      let started: ModelCallStart;
      try {
        started = modelCallStart.parse(
          await this.#authorization.beginModelCall(
            {
              worldId: this.#worldId,
              turnId: input.turnId,
              selectionId: input.selectionId,
              ...(ingressBinding === null ? {} : { ingressBinding }),
            },
            context.onBehalfOf,
          ),
        );
      } catch {
        return halt('authorization-refused');
      }
      const { call, projection } = started;
      if (
        call.world_id !== this.#worldId ||
        call.case_id !== this.#caseId ||
        call.turn_id !== input.turnId ||
        call.selection_id !== input.selectionId ||
        call.card_id !== lane.cardId ||
        call.card_version !== lane.cardVersion ||
        call.requested_id !== lane.requestedId ||
        call.projection_item_count !== projection.items.length ||
        canonicalize(call.projection_item_ids) !== canonicalize(projection.items.map((item) => item.id)) ||
        canonicalize(call.ingress_binding) !== canonicalize(ingressBinding) ||
        call.session_id !== (ingressBinding === null ? null : (context.onBehalfOf?.session_id ?? null)) ||
        !verifyDigest(call.projection_digest, digestFor('conversation-projection', projection)) ||
        projection.world_id !== this.#worldId ||
        projection.case_id !== this.#caseId ||
        projection.provider !== lane.cardId ||
        projection.role !== 'acting'
      ) {
        return halt('authorization-refused');
      }

      const haltStarted = async (
        code: ModelTurnErrorCode,
        failureReason: ModelCallFailureReason,
        providerDisclosure: 'possible' | 'confirmed',
        servedId: string | null,
      ): Promise<never> => {
        this.#quarantine.destroy(input.turnId);
        this.#haltedLanes.add(key);
        try {
          await this.#authorization.failModelCall(
            this.#worldId,
            modelCallFailureRequest.parse({
              call_id: call.call_id,
              turn_id: call.turn_id,
              selection_id: call.selection_id,
              projection_digest: call.projection_digest,
              failure_reason: failureReason,
              provider_disclosure: providerDisclosure,
              served_id: servedId,
            }),
            context.onBehalfOf,
          );
        } catch {
          // The durable open attempt remains explicitly indeterminate; never synthesize a terminal outcome.
        }
        throw new ModelTurnError(code, providerDisclosure, servedId);
      };

      let rawResponse: ActingResponse;
      try {
        context.onProviderAttempt?.();
        rawResponse = await lane.adapter.act({
          messages: projectionPrompt(projection),
          maxOutputTokens: input.maxOutputTokens,
        });
      } catch (error) {
        const failure = providerFailureEvidence(error);
        return await haltStarted('provider-failure', failure.failureReason, failure.providerDisclosure, null);
      }
      let parsedResponse: ReturnType<typeof actingResponse.safeParse>;
      try {
        parsedResponse = actingResponse.safeParse(rawResponse);
      } catch {
        return await haltStarted('provider-protocol', 'malformed-response', 'confirmed', null);
      }
      if (!parsedResponse.success) {
        const failure = protocolFailureEvidence(rawResponse);
        return await haltStarted('provider-protocol', failure.failureReason, 'confirmed', failure.servedId);
      }
      const response = parsedResponse.data;
      if (response.lane !== lane.lane || response.requestedId !== lane.requestedId) {
        return await haltStarted('provider-protocol', 'malformed-response', 'confirmed', response.servedId);
      }

      const parsedRequest = modelOutputAdmissionRequest.safeParse({
        turn_id: input.turnId,
        selection_id: call.selection_id,
        mandate_id: call.mandate_id,
        mandate_version: call.mandate_version,
        card_id: lane.cardId,
        card_version: lane.cardVersion,
        requested_id: lane.requestedId,
        served_id: response.servedId,
        projection_digest: digestFor('conversation-projection', projection),
        content: response.content,
      });
      if (!parsedRequest.success) {
        return await haltStarted('provider-protocol', 'malformed-response', 'confirmed', response.servedId);
      }
      const request = parsedRequest.data;
      let admissionEnvelope: ModelCallAdmission;
      try {
        admissionEnvelope = modelCallAdmission.parse(
          await this.#authorization.admitModelOutput(
            this.#worldId,
            call.call_id,
            request,
            context.onBehalfOf,
          ),
        );
      } catch (error) {
        return await haltStarted(
          'authorization-refused',
          isSystemUseInvalidation(error) ? 'system-use-invalidated' : 'authorization-invalidated',
          'confirmed',
          response.servedId,
        );
      }
      if (admissionEnvelope.call_id !== call.call_id) {
        return halt('admission-binding-invalid', 'confirmed', response.servedId);
      }
      const admission = admissionEnvelope.decision;
      if (!bindingMatches(admission, request, this.#caseId)) {
        return halt('admission-binding-invalid', 'confirmed', response.servedId);
      }
      if (admission.disposition === 'withheld') {
        if (admissionEnvelope.release !== null) return halt('admission-binding-invalid', 'confirmed', response.servedId);
        this.#quarantine.destroy(input.turnId);
        this.#haltedLanes.add(key);
        return { disposition: 'withheld', admission };
      }
      try {
        if (ingressBinding === null) {
          if (admissionEnvelope.release !== null) {
            return halt('admission-binding-invalid', 'confirmed', response.servedId);
          }
          return {
            disposition: 'quarantined',
            admission,
            quarantine: sealQuarantinedOutput(
              this.#quarantine,
              call.call_id,
              request,
              admission,
              this.#caseId,
              null,
            ),
          };
        }
        const release = admissionEnvelope.release;
        const claim = context.onBehalfOf;
        if (release === null || release.call_id !== call.call_id || claim === undefined) {
          return halt('admission-binding-invalid', 'confirmed', response.servedId);
        }
        sealQuarantinedOutput(
          this.#quarantine,
          call.call_id,
          request,
          admission,
          this.#caseId,
          release.release_id,
        );
        let ingestion: OutputReleaseConsumeResult;
        try {
          ingestion = outputReleaseConsumeResult.parse(
            await consumeQuarantinedOutput(
              this.#quarantine,
              input.turnId,
              release.release_id,
              (content) =>
                (this.#authorization.consumeOutputRelease as NonNullable<
                  ModelTurnAuthorizationClient['consumeOutputRelease']
                >)(this.#worldId, release.release_id, content, claim),
            ),
          );
        } catch (error) {
          if (
            error instanceof RuntimeDependencyError &&
            error.httpStatus >= 400 &&
            error.httpStatus < 500
          ) {
            this.#haltedLanes.add(key);
            throw new ModelTurnError('authorization-refused', 'confirmed', response.servedId);
          }
          let status: OutputReleaseStatusProjection;
          try {
            status = outputReleaseStatusProjection.parse(
              await (this.#authorization.outputReleaseStatus as NonNullable<
                ModelTurnAuthorizationClient['outputReleaseStatus']
              >)(this.#worldId, release.release_id, claim),
            );
          } catch {
            this.#haltedLanes.add(key);
            throw new ModelTurnError('authorization-refused', 'confirmed', response.servedId);
          }
          if (status.state !== 'consumed' || status.consumption_result === null) {
            this.#haltedLanes.add(key);
            throw new ModelTurnError('authorization-refused', 'confirmed', response.servedId);
          }
          ingestion = outputReleaseConsumeResult.parse({
            kind: 'output_release_consumption_result',
            release_id: status.release_id,
            state: 'consumed',
            ...status.consumption_result,
          });
        }
        if (ingestion.release_id !== release.release_id || ingestion.state !== 'consumed') {
          return halt('admission-binding-invalid', 'confirmed', response.servedId);
        }
        return { disposition: 'released', admission, ingestion };
      } catch (error) {
        if (error instanceof ModelTurnError) throw error;
        return halt(
          error instanceof ModelTurnError ? error.code : 'admission-binding-invalid',
          'confirmed',
          response.servedId,
        );
      }
    } finally {
      this.#busyLanes.delete(key);
    }
  }
}
