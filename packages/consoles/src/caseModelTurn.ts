// SPDX-License-Identifier: MIT
/** M5.9 browser-safe native model-turn preparation and metadata-only status. */
import { randomBytes, randomUUID } from 'node:crypto';

import {
  currentModelSelectionProjection,
  id,
  modelId,
  modelSelectionTarget,
  restrictionTagSet,
  timestamp,
  type CurrentModelSelectionProjection,
  type ModelSelectionTarget,
} from 'gate-core';
import { z } from 'zod';

import {
  ModelTurnError,
  ModelOutputQuarantine,
  type ModelTurnOutcome,
  type QuarantinedModelOutputRef,
} from './modelTurnCoordinator.js';
import type { CaseSessionRecord } from './caseSessionStore.js';

const MAX_MODEL_TURN_PREPARATION_TTL_MS = 2 * 60 * 1_000;
const MAX_MODEL_TURN_RECORDS = 128;

export const browserModelTurnPreparationRequest = z.object({}).strict();
export const browserModelTurnUseRequest = z.object({ preparation_id: id }).strict();

export const browserModelTurnPreparation = z
  .object({
    preparation_id: id,
    turn_id: id,
    selection_id: id,
    target: modelSelectionTarget,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict();
export type BrowserModelTurnPreparation = z.infer<typeof browserModelTurnPreparation>;

const browserQuarantineRef = z
  .object({
    release_state: z.literal('sealed-no-release-path'),
    call_id: id,
    projection_digest: z.string().regex(/^[0-9a-f]{64}$/),
    output_digest: z.string().regex(/^[0-9a-f]{64}$/),
    derived_tags: restrictionTagSet,
  })
  .strict();

const terminalReason = z.enum([
  'authorization-refused',
  'provider-failure',
  'provider-protocol',
  'quarantine-capacity',
  'admission-binding-invalid',
  'lane-unconfigured',
  'lane-halted',
  'lane-busy',
  'turn-replay',
  'output-withheld',
  'selection-changed',
  'session-ended',
  'runtime-failure',
]);
export type BrowserModelTurnTerminalReason = z.infer<typeof terminalReason>;

export const browserModelTurnStatus = z
  .object({
    turn_id: id,
    selection_id: id,
    target: modelSelectionTarget,
    state: z.enum(['prepared', 'running', 'quarantined', 'released', 'withheld', 'discarded', 'failed']),
    provider_disclosure: z.enum(['none', 'possible', 'confirmed']),
    requested_id: modelId,
    served_id: modelId.nullable(),
    terminal_reason: terminalReason.nullable(),
    quarantine: browserQuarantineRef.nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    if ((value.state === 'quarantined') !== (value.quarantine !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['quarantine'],
        message: 'only a quarantined turn exposes quarantine metadata',
      });
    }
    if (value.state === 'quarantined' && value.provider_disclosure !== 'confirmed') {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['provider_disclosure'],
        message: 'quarantined output requires confirmed provider disclosure',
      });
    }
    if (value.served_id !== null && value.provider_disclosure !== 'confirmed') {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['served_id'],
        message: 'served model evidence requires confirmed provider disclosure',
      });
    }
    const terminal = ['quarantined', 'withheld', 'discarded', 'failed'].includes(value.state);
    if (terminal !== (value.terminal_reason !== null || value.state === 'quarantined')) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['terminal_reason'],
        message: 'terminal model-turn status requires a fixed reason except for retained quarantine',
      });
    }
  });
export type BrowserModelTurnStatus = z.infer<typeof browserModelTurnStatus>;

interface ModelTurnRecord {
  readonly preparation_id: string;
  readonly turn_id: string;
  readonly session_id: string;
  readonly session_expires_at: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly authorization_boot_id: string;
  readonly selection_id: string;
  readonly target: ModelSelectionTarget;
  readonly issued_at: string;
  readonly expires_at: string;
  state: BrowserModelTurnStatus['state'];
  provider_disclosure: BrowserModelTurnStatus['provider_disclosure'];
  served_id: string | null;
  terminal_reason: BrowserModelTurnTerminalReason | null;
  quarantine: BrowserModelTurnStatus['quarantine'];
  discard_reason: Extract<BrowserModelTurnTerminalReason, 'selection-changed' | 'session-ended'> | null;
}

export interface BegunModelTurn {
  readonly preparationId: string;
  readonly turnId: string;
  readonly selectionId: string;
  readonly target: ModelSelectionTarget;
}

export interface CaseModelTurnStoreOptions {
  readonly ttlMs?: number;
  readonly maxRecords?: number;
  readonly now?: () => string;
  readonly nextPreparationId?: () => string;
  readonly nextTurnId?: () => string;
}

function sameSession(record: ModelTurnRecord, session: CaseSessionRecord): boolean {
  return (
    record.session_id === session.session_id &&
    record.role === session.role &&
    record.world_id === session.world_id &&
    record.case_id === session.case_id &&
    record.authorization_boot_id === session.authorization_boot_id
  );
}

function publicQuarantine(input: QuarantinedModelOutputRef): BrowserModelTurnStatus['quarantine'] {
  return browserQuarantineRef.parse({
    release_state: input.release_state,
    call_id: input.call_id,
    projection_digest: input.projection_digest,
    output_digest: input.output_digest,
    derived_tags: input.derived_tags,
  });
}

export class CaseModelTurnStore {
  readonly #recordsByTurn = new Map<string, ModelTurnRecord>();
  readonly #turnByPreparation = new Map<string, string>();
  readonly #currentPreparationBySession = new Map<string, string>();
  readonly #ttlMs: number;
  readonly #maxRecords: number;
  readonly #now: () => string;
  readonly #nextPreparationId: () => string;
  readonly #nextTurnId: () => string;

  constructor(options: CaseModelTurnStoreOptions = {}) {
    this.#ttlMs = options.ttlMs ?? MAX_MODEL_TURN_PREPARATION_TTL_MS;
    if (!Number.isInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > MAX_MODEL_TURN_PREPARATION_TTL_MS) {
      throw new RangeError('browser model-turn preparation TTL must be from 1 through 120000 milliseconds');
    }
    this.#maxRecords = options.maxRecords ?? MAX_MODEL_TURN_RECORDS;
    if (!Number.isInteger(this.#maxRecords) || this.#maxRecords < 1 || this.#maxRecords > MAX_MODEL_TURN_RECORDS) {
      throw new RangeError('browser model-turn record capacity must be from 1 through 128');
    }
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#nextPreparationId = options.nextPreparationId ?? (() => `mtp_${randomBytes(16).toString('hex')}`);
    this.#nextTurnId = options.nextTurnId ?? (() => `turn_${randomUUID().replaceAll('-', '')}`);
  }

  #deletePrepared(record: ModelTurnRecord): void {
    this.#recordsByTurn.delete(record.turn_id);
    this.#turnByPreparation.delete(record.preparation_id);
    if (this.#currentPreparationBySession.get(record.session_id) === record.preparation_id) {
      this.#currentPreparationBySession.delete(record.session_id);
    }
  }

  #discard(
    record: ModelTurnRecord,
    reason: Extract<BrowserModelTurnTerminalReason, 'selection-changed' | 'session-ended'>,
    quarantine: ModelOutputQuarantine,
  ): void {
    if (record.state === 'prepared') {
      this.#deletePrepared(record);
      return;
    }
    record.discard_reason = reason;
    if (record.state === 'quarantined') {
      quarantine.destroy(record.turn_id);
    }
    if (record.state !== 'running') {
      record.state = 'discarded';
      record.terminal_reason = reason;
      record.quarantine = null;
    }
  }

  create(session: CaseSessionRecord, currentInput: CurrentModelSelectionProjection): BrowserModelTurnPreparation {
    const current = currentModelSelectionProjection.parse(currentInput);
    const at = timestamp.parse(this.#now());
    if (
      current.state !== 'selected' ||
      current.authorization_boot_id !== session.authorization_boot_id ||
      current.case_id !== session.case_id ||
      current.selection.world_id !== session.world_id ||
      current.selection.case_id !== session.case_id ||
      session.state !== 'active' ||
      session.expires_at <= at
    ) {
      throw new Error('model-turn-preparation-binding-invalid');
    }
    const priorPreparation = this.#currentPreparationBySession.get(session.session_id);
    if (priorPreparation !== undefined) {
      const priorTurn = this.#turnByPreparation.get(priorPreparation);
      const prior = priorTurn === undefined ? undefined : this.#recordsByTurn.get(priorTurn);
      if (prior?.state === 'prepared') this.#deletePrepared(prior);
    }
    if (this.#recordsByTurn.size >= this.#maxRecords) throw new Error('model-turn-capacity');
    const preparationId = id.parse(this.#nextPreparationId());
    const turnId = id.parse(this.#nextTurnId());
    if (this.#turnByPreparation.has(preparationId) || this.#recordsByTurn.has(turnId)) {
      throw new Error('model-turn identifier source repeated a value');
    }
    const expiresAt = timestamp.parse(
      new Date(Math.min(Date.parse(at) + this.#ttlMs, Date.parse(session.expires_at))).toISOString(),
    );
    if (expiresAt <= at) throw new Error('model-turn-preparation-expired');
    const target = modelSelectionTarget.parse({
      card_id: current.selection.target.card_id,
      card_version: current.selection.target.card_version,
      requested_id: current.selection.target.requested_id,
    });
    const record: ModelTurnRecord = {
      preparation_id: preparationId,
      turn_id: turnId,
      session_id: session.session_id,
      session_expires_at: session.expires_at,
      role: session.role,
      world_id: session.world_id,
      case_id: session.case_id,
      authorization_boot_id: session.authorization_boot_id,
      selection_id: current.selection.selection_id,
      target,
      issued_at: at,
      expires_at: expiresAt,
      state: 'prepared',
      provider_disclosure: 'none',
      served_id: null,
      terminal_reason: null,
      quarantine: null,
      discard_reason: null,
    };
    this.#recordsByTurn.set(turnId, record);
    this.#turnByPreparation.set(preparationId, turnId);
    this.#currentPreparationBySession.set(session.session_id, preparationId);
    return browserModelTurnPreparation.parse({
      preparation_id: preparationId,
      turn_id: turnId,
      selection_id: record.selection_id,
      target,
      issued_at: at,
      expires_at: expiresAt,
    });
  }

  beginUse(preparationIdInput: string, session: CaseSessionRecord): BegunModelTurn | null {
    const preparationId = id.parse(preparationIdInput);
    const turnId = this.#turnByPreparation.get(preparationId);
    const record = turnId === undefined ? undefined : this.#recordsByTurn.get(turnId);
    const at = timestamp.parse(this.#now());
    if (
      record === undefined ||
      record.state !== 'prepared' ||
      !sameSession(record, session) ||
      record.expires_at <= at ||
      record.session_expires_at <= at
    ) {
      return null;
    }
    record.state = 'running';
    this.#currentPreparationBySession.delete(record.session_id);
    return {
      preparationId,
      turnId: record.turn_id,
      selectionId: record.selection_id,
      target: record.target,
    };
  }

  markProviderPossible(turnIdInput: string): void {
    const record = this.#recordsByTurn.get(id.parse(turnIdInput));
    if (record?.state === 'running') record.provider_disclosure = 'possible';
  }

  complete(turnIdInput: string, outcome: ModelTurnOutcome, quarantine: ModelOutputQuarantine): BrowserModelTurnStatus {
    const record = this.#recordsByTurn.get(id.parse(turnIdInput));
    if (record === undefined || record.state !== 'running') throw new Error('model-turn-state-invalid');
    const admission = outcome.admission;
    const bindingInvalid =
      outcome.disposition === 'released' ||
      admission.disposition !== (outcome.disposition === 'quarantined' ? 'admitted' : 'withheld') ||
      admission.case_id !== record.case_id ||
      admission.turn_id !== record.turn_id ||
      admission.selection_id !== record.selection_id ||
      admission.card_id !== record.target.card_id ||
      admission.card_version !== record.target.card_version ||
      admission.requested_id !== record.target.requested_id ||
      (outcome.disposition === 'quarantined' &&
        (outcome.quarantine.case_id !== record.case_id ||
          outcome.quarantine.turn_id !== record.turn_id ||
          outcome.quarantine.selection_id !== record.selection_id ||
          outcome.quarantine.card_id !== record.target.card_id ||
          outcome.quarantine.card_version !== record.target.card_version ||
          outcome.quarantine.requested_id !== record.target.requested_id ||
          outcome.quarantine.served_id !== admission.served_id ||
          outcome.quarantine.projection_digest !== admission.projection_digest ||
          outcome.quarantine.output_digest !== admission.output_digest ||
          JSON.stringify(outcome.quarantine.derived_tags) !== JSON.stringify(outcome.admission.derived_tags)));
    if (bindingInvalid) {
      quarantine.destroy(record.turn_id);
      throw new ModelTurnError('admission-binding-invalid', 'confirmed', admission.served_id);
    }
    if (outcome.disposition === 'withheld') {
      record.state = 'withheld';
      record.provider_disclosure = 'confirmed';
      record.served_id = outcome.admission.served_id;
      record.terminal_reason = 'output-withheld';
    } else if (outcome.disposition === 'quarantined') {
      record.state = 'quarantined';
      record.provider_disclosure = 'confirmed';
      record.served_id = outcome.admission.served_id;
      record.quarantine = publicQuarantine(outcome.quarantine);
    } else {
      throw new ModelTurnError('admission-binding-invalid', 'confirmed', admission.served_id);
    }
    if (record.discard_reason !== null) this.#discard(record, record.discard_reason, quarantine);
    return this.#project(record);
  }

  fail(turnIdInput: string, error: ModelTurnError | null): BrowserModelTurnStatus {
    const record = this.#recordsByTurn.get(id.parse(turnIdInput));
    if (record === undefined || record.state !== 'running') throw new Error('model-turn-state-invalid');
    if (error?.providerDisclosure === 'confirmed') {
      record.provider_disclosure = 'confirmed';
      record.served_id = error.servedId;
    } else if (error?.providerDisclosure === 'possible' && record.provider_disclosure === 'none') {
      record.provider_disclosure = 'possible';
    }
    if (record.discard_reason !== null) {
      record.state = 'discarded';
      record.terminal_reason = record.discard_reason;
      record.quarantine = null;
      return this.#project(record);
    }
    record.state = 'failed';
    record.terminal_reason =
      error === null || error.code === 'invalid-configuration' ? 'runtime-failure' : error.code;
    record.quarantine = null;
    return this.#project(record);
  }

  status(turnIdInput: string, session: CaseSessionRecord): BrowserModelTurnStatus | null {
    const record = this.#recordsByTurn.get(id.parse(turnIdInput));
    return record === undefined || !sameSession(record, session) ? null : this.#project(record);
  }

  discardSelection(selectionIdInput: string, quarantine: ModelOutputQuarantine): void {
    const selectionId = id.parse(selectionIdInput);
    for (const record of this.#recordsByTurn.values()) {
      if (record.selection_id === selectionId) this.#discard(record, 'selection-changed', quarantine);
    }
  }

  reconcileSelection(
    worldIdInput: string,
    caseIdInput: string,
    currentSelectionId: string | null,
    quarantine: ModelOutputQuarantine,
  ): void {
    for (const record of this.#recordsByTurn.values()) {
      if (
        record.world_id === worldIdInput &&
        record.case_id === caseIdInput &&
        record.selection_id !== currentSelectionId
      ) {
        this.#discard(record, 'selection-changed', quarantine);
      }
    }
  }

  discardSession(sessionIdInput: string, quarantine: ModelOutputQuarantine): void {
    const sessionId = id.parse(sessionIdInput);
    for (const record of this.#recordsByTurn.values()) {
      if (record.session_id === sessionId) this.#discard(record, 'session-ended', quarantine);
    }
  }

  expire(quarantine: ModelOutputQuarantine): void {
    const at = timestamp.parse(this.#now());
    for (const record of this.#recordsByTurn.values()) {
      if (record.session_expires_at <= at) this.#discard(record, 'session-ended', quarantine);
      else if (record.state === 'prepared' && record.expires_at <= at) this.#deletePrepared(record);
    }
  }

  #project(record: ModelTurnRecord): BrowserModelTurnStatus {
    return browserModelTurnStatus.parse({
      turn_id: record.turn_id,
      selection_id: record.selection_id,
      target: record.target,
      state: record.state,
      provider_disclosure: record.provider_disclosure,
      requested_id: record.target.requested_id,
      served_id: record.served_id,
      terminal_reason: record.terminal_reason,
      quarantine: record.quarantine,
    });
  }
}
