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
  modelOutputAdmission,
  modelOutputAdmissionRequest,
  sortedRestrictionTags,
  verifyDigest,
  worldId,
  type ConversationProjection,
  type ModelCallAdmission,
  type ModelCallFailedRecord,
  type ModelCallFailureReason,
  type ModelCallFailureRequest,
  type ModelCallStart,
  type ModelOutputAdmission,
  type ModelOutputAdmissionRequest,
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
    mandateId: id,
    mandateVersion: integer.min(1),
    cardId: cardSlug,
    cardVersion: integer.min(1),
    requestedId: modelId,
    maxOutputTokens: integer.min(1).max(8_192),
  })
  .strict();

const quarantinedModelOutputRef = z
  .object({
    kind: z.literal('quarantined_model_output'),
    release_state: z.literal('sealed-no-release-path'),
    call_id: id,
    case_id: id,
    turn_id: id,
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

export class ModelTurnError extends Error {
  constructor(readonly code: ModelTurnErrorCode) {
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
  beginModelCall(input: {
    readonly worldId: string;
    readonly turnId: string;
    readonly mandateId: string;
    readonly mandateVersion: number;
    readonly cardId: string;
    readonly cardVersion: number;
    readonly requestedId: string;
  }): Promise<ModelCallStart>;
  admitModelOutput(
    worldIdInput: string,
    callIdInput: string,
    input: ModelOutputAdmissionRequest,
  ): Promise<ModelCallAdmission>;
  failModelCall(worldIdInput: string, input: ModelCallFailureRequest): Promise<ModelCallFailedRecord>;
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
  readonly bytes: Buffer;
}

type QuarantineSealer = (
  callId: string,
  request: ModelOutputAdmissionRequest,
  decision: AdmittedOutput,
  caseId: string,
) => QuarantinedModelOutputRef;

/** Module-private capability: importers can inspect or destroy quarantine entries but cannot create one. */
const quarantineSealers = new WeakMap<ModelOutputQuarantine, QuarantineSealer>();

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
 * Process-private holding area. M5.4 deliberately exposes metadata and destruction only:
 * no exported method can seal, read, or release the held bytes. Sealing is a module-private
 * coordinator capability, which provides structural confinement rather than cryptographic
 * proof of authorization provenance. A later reviewed slice must add a distinct, single-use
 * validated consumer rather than treating presence here as safety clearance.
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
    quarantineSealers.set(this, (callId, request, decision, caseId) => this.#seal(callId, request, decision, caseId));
  }

  #seal(
    callIdInput: string,
    requestInput: ModelOutputAdmissionRequest,
    decisionInput: AdmittedOutput,
    caseIdInput: string,
  ): QuarantinedModelOutputRef {
    const request = modelOutputAdmissionRequest.parse(requestInput);
    const decision = modelOutputAdmission.parse(decisionInput);
    const callId = id.parse(callIdInput);
    const caseId = id.parse(caseIdInput);
    if (decision.disposition !== 'admitted' || !bindingMatches(decision, request, caseId)) {
      throw new ModelTurnError('admission-binding-invalid');
    }
    if (this.#seen.has(request.turn_id)) throw new ModelTurnError('turn-replay');
    const ref = quarantinedModelOutputRef.parse({
      kind: 'quarantined_model_output',
      release_state: 'sealed-no-release-path',
      call_id: callId,
      case_id: caseId,
      turn_id: request.turn_id,
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
    this.#held.set(request.turn_id, { ref, bytes });
    this.#heldBytes += bytes.byteLength;
    return ref;
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
): QuarantinedModelOutputRef {
  const seal = quarantineSealers.get(quarantine);
  if (seal === undefined) throw new ModelTurnError('invalid-configuration');
  return seal(callId, request, decision, caseId);
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

  async run(inputValue: ModelTurnInput): Promise<ModelTurnOutcome> {
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

      const halt = (code: ModelTurnErrorCode): never => {
        this.#quarantine.destroy(input.turnId);
        this.#haltedLanes.add(key);
        throw new ModelTurnError(code);
      };

      let started: ModelCallStart;
      try {
        started = modelCallStart.parse(
          await this.#authorization.beginModelCall({
            worldId: this.#worldId,
            turnId: input.turnId,
            mandateId: input.mandateId,
            mandateVersion: input.mandateVersion,
            cardId: lane.cardId,
            cardVersion: lane.cardVersion,
            requestedId: lane.requestedId,
          }),
        );
      } catch {
        return halt('authorization-refused');
      }
      const { call, projection } = started;
      if (
        call.world_id !== this.#worldId ||
        call.case_id !== this.#caseId ||
        call.turn_id !== input.turnId ||
        call.mandate_id !== input.mandateId ||
        call.mandate_version !== input.mandateVersion ||
        call.card_id !== lane.cardId ||
        call.card_version !== lane.cardVersion ||
        call.requested_id !== lane.requestedId ||
        call.projection_item_count !== projection.items.length ||
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
              mandate_id: call.mandate_id,
              mandate_version: call.mandate_version,
              card_id: call.card_id,
              card_version: call.card_version,
              requested_id: call.requested_id,
              projection_digest: call.projection_digest,
              failure_reason: failureReason,
              provider_disclosure: providerDisclosure,
              served_id: servedId,
            }),
          );
        } catch {
          // The durable open attempt remains explicitly indeterminate; never synthesize a terminal outcome.
        }
        throw new ModelTurnError(code);
      };

      let rawResponse: ActingResponse;
      try {
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
        mandate_id: input.mandateId,
        mandate_version: input.mandateVersion,
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
          await this.#authorization.admitModelOutput(this.#worldId, call.call_id, request),
        );
      } catch (error) {
        return await haltStarted(
          'authorization-refused',
          isSystemUseInvalidation(error) ? 'system-use-invalidated' : 'authorization-invalidated',
          'confirmed',
          response.servedId,
        );
      }
      if (admissionEnvelope.call_id !== call.call_id) return halt('admission-binding-invalid');
      const admission = admissionEnvelope.decision;
      if (!bindingMatches(admission, request, this.#caseId)) return halt('admission-binding-invalid');
      if (admission.disposition === 'withheld') {
        this.#quarantine.destroy(input.turnId);
        this.#haltedLanes.add(key);
        return { disposition: 'withheld', admission };
      }
      try {
        return {
          disposition: 'quarantined',
          admission,
          quarantine: sealQuarantinedOutput(this.#quarantine, call.call_id, request, admission, this.#caseId),
        };
      } catch (error) {
        return halt(error instanceof ModelTurnError ? error.code : 'admission-binding-invalid');
      }
    } finally {
      this.#busyLanes.delete(key);
    }
  }
}
