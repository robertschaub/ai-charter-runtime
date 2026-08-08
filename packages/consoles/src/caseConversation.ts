// SPDX-License-Identifier: MIT
/** M5.10 browser message preparation, turn status, and transcript redaction boundary. */
import { randomBytes, randomUUID } from 'node:crypto';

import {
  conversationProcessProjection,
  id,
  modelId,
  modelSelectionTarget,
  timestamp,
  type ConversationProcessProjection,
  type CurrentModelSelectionProjection,
  type ModelSelectionTarget,
} from 'gate-core';
import { z } from 'zod';

import {
  browserModelTurnStatus,
  type BrowserModelTurnStatus,
  type BrowserModelTurnTerminalReason,
} from './caseModelTurn.js';
import {
  ModelOutputQuarantine,
  ModelTurnError,
  type MessageBoundModelTurnInput,
  type ModelTurnOutcome,
} from './modelTurnCoordinator.js';
import type { CaseSessionRecord } from './caseSessionStore.js';

const MAX_MESSAGE_BYTES = 8_192;
const MAX_PREPARATION_TTL_MS = 2 * 60 * 1_000;
const MAX_TURNS = 128;

export const browserMessagePreparationRequest = z.object({ message: z.string() }).strict();
export const browserMessageUseRequest = z.object({ preparation_id: id }).strict();

export const browserMessagePreparation = z
  .object({
    preparation_id: id,
    message_id: id,
    turn_id: id,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict();
export type BrowserMessagePreparation = z.infer<typeof browserMessagePreparation>;

const browserConversationEventBase = z.object({
  message_id: id,
  turn_id: id,
  text: z.string(),
  recorded_at: timestamp,
});

export const browserConversationProjection = z
  .object({
    case_id: id,
    conversation_version: z.number().int().min(0),
    events: z
      .array(
        z.discriminatedUnion('speaker', [
          browserConversationEventBase.extend({ speaker: z.literal('case_officer') }).strict(),
          browserConversationEventBase
            .extend({
              speaker: z.literal('model'),
              requested_id: modelId,
              served_id: modelId,
              classification: z.literal('inferred-unconfirmed'),
            })
            .strict(),
        ]),
      )
      .max(128),
  })
  .strict();
export type BrowserConversationProjection = z.infer<typeof browserConversationProjection>;

export function toBrowserConversation(input: ConversationProcessProjection): BrowserConversationProjection {
  const projection = conversationProcessProjection.parse(input);
  return browserConversationProjection.parse({
    case_id: projection.case_id,
    conversation_version: projection.conversation_version,
    events: projection.events.map((event) =>
      event.speaker === 'case_officer'
        ? {
            speaker: 'case_officer',
            message_id: event.message_id,
            turn_id: event.turn_id,
            text: event.text,
            recorded_at: event.recorded_at,
          }
        : {
            speaker: 'model',
            message_id: event.message_id,
            turn_id: event.turn_id,
            text: event.text,
            recorded_at: event.recorded_at,
            requested_id: event.requested_id,
            served_id: event.served_id,
            classification: 'inferred-unconfirmed',
          },
    ),
  });
}

interface MessageTurnRecord {
  readonly preparationId: string;
  readonly messageId: string;
  readonly turnId: string;
  readonly sessionId: string;
  readonly sessionExpiresAt: string;
  readonly worldId: string;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly selectionId: string;
  readonly target: ModelSelectionTarget;
  readonly issuedAt: string;
  readonly expiresAt: string;
  bytes: Buffer | null;
  state: BrowserModelTurnStatus['state'];
  providerDisclosure: BrowserModelTurnStatus['provider_disclosure'];
  servedId: string | null;
  terminalReason: BrowserModelTurnTerminalReason | null;
}

export interface CaseConversationStoreOptions {
  readonly ttlMs?: number;
  readonly maxTurns?: number;
  readonly maxOutputTokens?: number;
  readonly now?: () => string;
  readonly nextPreparationId?: () => string;
  readonly nextMessageId?: () => string;
  readonly nextTurnId?: () => string;
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

function messageBytes(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  if (
    !isWellFormedUnicode(value) ||
    !/\S/u.test(value) ||
    bytes.byteLength > MAX_MESSAGE_BYTES ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    bytes.fill(0);
    throw new Error('message-preparation-invalid');
  }
  return bytes;
}

function sameSession(record: MessageTurnRecord, session: CaseSessionRecord): boolean {
  return (
    record.sessionId === session.session_id &&
    record.worldId === session.world_id &&
    record.caseId === session.case_id &&
    record.authorizationBootId === session.authorization_boot_id
  );
}

export class CaseConversationStore {
  readonly #records = new Map<string, MessageTurnRecord>();
  readonly #turnByPreparation = new Map<string, string>();
  readonly #currentPreparationBySession = new Map<string, string>();
  readonly #ttlMs: number;
  readonly #maxTurns: number;
  readonly #maxOutputTokens: number;
  readonly #now: () => string;
  readonly #nextPreparationId: () => string;
  readonly #nextMessageId: () => string;
  readonly #nextTurnId: () => string;

  constructor(options: CaseConversationStoreOptions = {}) {
    this.#ttlMs = options.ttlMs ?? MAX_PREPARATION_TTL_MS;
    if (!Number.isInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > MAX_PREPARATION_TTL_MS) {
      throw new RangeError('message preparation TTL must be from 1 through 120000 milliseconds');
    }
    this.#maxTurns = options.maxTurns ?? MAX_TURNS;
    if (!Number.isInteger(this.#maxTurns) || this.#maxTurns < 1 || this.#maxTurns > MAX_TURNS) {
      throw new RangeError('message turn capacity must be from 1 through 128');
    }
    this.#maxOutputTokens = options.maxOutputTokens ?? 1_024;
    if (!Number.isInteger(this.#maxOutputTokens) || this.#maxOutputTokens < 1 || this.#maxOutputTokens > 8_192) {
      throw new RangeError('message max output tokens must be from 1 through 8192');
    }
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#nextPreparationId = options.nextPreparationId ?? (() => `msgp_${randomBytes(16).toString('hex')}`);
    this.#nextMessageId = options.nextMessageId ?? (() => `msg_${randomUUID().replaceAll('-', '')}`);
    this.#nextTurnId = options.nextTurnId ?? (() => `turn_${randomUUID().replaceAll('-', '')}`);
  }

  #burnBytes(record: MessageTurnRecord): void {
    record.bytes?.fill(0);
    record.bytes = null;
  }

  #removePrepared(record: MessageTurnRecord): void {
    this.#burnBytes(record);
    this.#turnByPreparation.delete(record.preparationId);
    if (this.#currentPreparationBySession.get(record.sessionId) === record.preparationId) {
      this.#currentPreparationBySession.delete(record.sessionId);
    }
    if (record.state === 'prepared') this.#records.delete(record.turnId);
  }

  create(
    message: string,
    session: CaseSessionRecord,
    current: CurrentModelSelectionProjection,
  ): BrowserMessagePreparation {
    const at = timestamp.parse(this.#now());
    const selected = current.selection;
    if (
      session.state !== 'active' ||
      session.expires_at <= at ||
      current.state !== 'selected' ||
      selected === null ||
      current.case_id !== session.case_id ||
      current.authorization_boot_id !== session.authorization_boot_id ||
      selected.world_id !== session.world_id ||
      selected.case_id !== session.case_id
    ) {
      throw new Error('message-preparation-binding-invalid');
    }
    const bytes = messageBytes(message);
    const priorId = this.#currentPreparationBySession.get(session.session_id);
    const priorTurn = priorId === undefined ? undefined : this.#turnByPreparation.get(priorId);
    const prior = priorTurn === undefined ? undefined : this.#records.get(priorTurn);
    if (prior?.state === 'prepared') this.#removePrepared(prior);
    if (this.#records.size >= this.#maxTurns) {
      bytes.fill(0);
      throw new Error('message-turn-capacity');
    }
    const preparationId = id.parse(this.#nextPreparationId());
    const messageId = id.parse(this.#nextMessageId());
    const turnId = id.parse(this.#nextTurnId());
    if (
      this.#turnByPreparation.has(preparationId) ||
      [...this.#records.values()].some((record) => record.messageId === messageId || record.turnId === turnId)
    ) {
      bytes.fill(0);
      throw new Error('message identifier source repeated a value');
    }
    const expiresAt = timestamp.parse(
      new Date(Math.min(Date.parse(at) + this.#ttlMs, Date.parse(session.expires_at))).toISOString(),
    );
    const target = modelSelectionTarget.parse({
      card_id: selected.target.card_id,
      card_version: selected.target.card_version,
      requested_id: selected.target.requested_id,
    });
    const record: MessageTurnRecord = {
      preparationId,
      messageId,
      turnId,
      sessionId: session.session_id,
      sessionExpiresAt: session.expires_at,
      worldId: session.world_id,
      caseId: session.case_id,
      authorizationBootId: session.authorization_boot_id,
      selectionId: selected.selection_id,
      target,
      issuedAt: at,
      expiresAt,
      bytes,
      state: 'prepared',
      providerDisclosure: 'none',
      servedId: null,
      terminalReason: null,
    };
    this.#records.set(turnId, record);
    this.#turnByPreparation.set(preparationId, turnId);
    this.#currentPreparationBySession.set(session.session_id, preparationId);
    return browserMessagePreparation.parse({ preparation_id: preparationId, message_id: messageId, turn_id: turnId, issued_at: at, expires_at: expiresAt });
  }

  async use(
    preparationIdInput: string,
    session: CaseSessionRecord,
    operation: (input: MessageBoundModelTurnInput) => Promise<ModelTurnOutcome>,
    quarantine: ModelOutputQuarantine,
  ): Promise<BrowserModelTurnStatus | null> {
    const preparationId = id.parse(preparationIdInput);
    const turnId = this.#turnByPreparation.get(preparationId);
    const record = turnId === undefined ? undefined : this.#records.get(turnId);
    const at = timestamp.parse(this.#now());
    if (
      record === undefined ||
      record.state !== 'prepared' ||
      !sameSession(record, session) ||
      record.expiresAt <= at ||
      record.sessionExpiresAt <= at ||
      record.bytes === null
    ) {
      return null;
    }
    record.state = 'running';
    this.#turnByPreparation.delete(preparationId);
    this.#currentPreparationBySession.delete(record.sessionId);
    const bytes = record.bytes;
    record.bytes = null;
    try {
      const outcome = await operation({
        messageId: record.messageId,
        text: bytes.toString('utf8'),
        turnId: record.turnId,
        selectionId: record.selectionId,
        cardId: record.target.card_id,
        cardVersion: record.target.card_version,
        requestedId: record.target.requested_id,
        maxOutputTokens: this.#maxOutputTokens,
      });
      const admission = outcome.admission;
      if (
        admission.disposition !== (outcome.disposition === 'withheld' ? 'withheld' : 'admitted') ||
        admission.case_id !== record.caseId ||
        admission.turn_id !== record.turnId ||
        admission.selection_id !== record.selectionId ||
        admission.card_id !== record.target.card_id ||
        admission.card_version !== record.target.card_version ||
        admission.requested_id !== record.target.requested_id
      ) {
        quarantine.destroy(record.turnId);
        throw new ModelTurnError('admission-binding-invalid', 'confirmed', admission.served_id);
      }
      if (outcome.disposition === 'quarantined') {
        quarantine.destroy(record.turnId);
        throw new ModelTurnError('admission-binding-invalid', 'confirmed', outcome.admission.served_id);
      }
      record.providerDisclosure = 'confirmed';
      record.servedId = outcome.admission.served_id;
      if (outcome.disposition === 'withheld') {
        record.state = 'withheld';
        record.terminalReason = 'output-withheld';
      } else {
        record.state = 'released';
        record.terminalReason = null;
      }
    } catch (error) {
      const failure = error instanceof ModelTurnError ? error : new ModelTurnError('authorization-refused');
      record.state = 'failed';
      record.providerDisclosure = failure.providerDisclosure;
      record.servedId = failure.servedId;
      record.terminalReason = failure.code === 'invalid-configuration' ? 'runtime-failure' : failure.code;
    } finally {
      bytes.fill(0);
    }
    return this.#project(record);
  }

  status(turnIdInput: string, session: CaseSessionRecord): BrowserModelTurnStatus | null {
    const record = this.#records.get(id.parse(turnIdInput));
    return record === undefined || !sameSession(record, session) ? null : this.#project(record);
  }

  burnForSession(sessionIdInput: string): void {
    const sessionId = id.parse(sessionIdInput);
    for (const record of [...this.#records.values()]) {
      if (record.sessionId !== sessionId) continue;
      if (record.state === 'prepared') this.#removePrepared(record);
    }
  }

  burnStaleForCase(worldIdInput: string, caseIdInput: string, currentSelectionId: string | null): void {
    for (const record of [...this.#records.values()]) {
      if (
        record.worldId === worldIdInput &&
        record.caseId === caseIdInput &&
        record.selectionId !== currentSelectionId &&
        record.state === 'prepared'
      ) {
        this.#removePrepared(record);
      }
    }
  }

  expire(): void {
    const at = timestamp.parse(this.#now());
    for (const record of [...this.#records.values()]) {
      if (record.state === 'prepared' && (record.expiresAt <= at || record.sessionExpiresAt <= at)) {
        this.#removePrepared(record);
      }
    }
  }

  clear(): void {
    for (const record of this.#records.values()) this.#burnBytes(record);
    this.#records.clear();
    this.#turnByPreparation.clear();
    this.#currentPreparationBySession.clear();
  }

  #project(record: MessageTurnRecord): BrowserModelTurnStatus {
    return browserModelTurnStatus.parse({
      turn_id: record.turnId,
      selection_id: record.selectionId,
      target: record.target,
      state: record.state,
      provider_disclosure: record.providerDisclosure,
      requested_id: record.target.requested_id,
      served_id: record.servedId,
      terminal_reason: record.terminalReason,
      quarantine: null,
    });
  }
}
