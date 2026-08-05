// SPDX-License-Identifier: MIT
/** ADR-010 browser-safe selection projections and process-private preparation state. */
import { randomBytes } from 'node:crypto';

import {
  approvedModelsProjection,
  currentModelSelectionProjection,
  id,
  integer,
  mandateState,
  modelCard,
  modelId,
  modelRole,
  modelSelectionCheckProjection,
  modelSelectionProjection,
  modelSelectionTarget,
  restrictionTagSet,
  timestamp,
  type CurrentModelSelectionProjection,
  type ModelSelectionCheckProjection,
  type ModelSelectionProjection,
  type ModelSelectionTarget,
} from 'gate-core';
import { z } from 'zod';

import type { CaseSessionRecord } from './caseSessionStore.js';

const MAX_BROWSER_PREPARATION_TTL_MS = 2 * 60 * 1_000;

const browserApprovedModelEntry = modelSelectionTarget
  .extend({
    roles: z.array(modelRole),
    data_classes: z.record(modelRole, restrictionTagSet),
    re_confirmation_required: z.boolean().optional(),
  })
  .strict();

export const browserApprovedModelEvidence = z
  .object({
    approval: browserApprovedModelEntry,
    effective_data_classes: z.record(modelRole, restrictionTagSet),
    card_status: z.enum(['current', 'superseded', 'withdrawn']),
    signature_status: z.enum(['valid', 'invalid']),
    integrity_alarm: z.boolean(),
    current_card: modelCard.nullable(),
  })
  .strict();
export type BrowserApprovedModelEvidence = z.infer<typeof browserApprovedModelEvidence>;

export const browserApprovedModelsProjection = z
  .object({
    mandate_id: id,
    mandate_version: integer.min(1),
    mandate_state: mandateState,
    default_acting_model: modelSelectionTarget,
    models: z.array(browserApprovedModelEvidence),
  })
  .strict();
export type BrowserApprovedModelsProjection = z.infer<typeof browserApprovedModelsProjection>;

export const browserModelSelectionTransition = z
  .object({
    selection_id: id,
    kind: z.enum(['initial', 'switch']),
    predecessor_selection_id: id.nullable(),
    mandate_id: id,
    mandate_version: integer.min(1),
    target: modelSelectionTarget,
    selected_at: timestamp,
    authority_effect: z.literal('none'),
  })
  .strict();

const browserModelSelectionObservation = z
  .object({
    served_id: modelId,
    model_resolution: z.enum(['exact', 'benign-resolution', 'mismatch']),
    terminal_outcome: z.enum(['admitted', 'withheld', 'failed']),
    observed_at: timestamp,
  })
  .strict();

export const browserCurrentModelSelectionProjection = z.discriminatedUnion('state', [
  z
    .object({
      state: z.literal('unselected'),
      case_id: id,
      selection: z.null(),
      latest_observation: z.null(),
    })
    .strict(),
  z
    .object({
      state: z.literal('selected'),
      case_id: id,
      selection: browserModelSelectionTransition,
      latest_observation: browserModelSelectionObservation.nullable(),
    })
    .strict(),
]);
export type BrowserCurrentModelSelectionProjection = z.infer<typeof browserCurrentModelSelectionProjection>;

export const browserModelSelectionPreparationRequest = z.object({ target: modelSelectionTarget }).strict();
export const browserModelSelectionUseRequest = z.object({ preparation_id: id }).strict();

export const browserModelSelectionPreparation = z
  .object({
    preparation_id: id,
    target: modelSelectionTarget,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict();
export type BrowserModelSelectionPreparation = z.infer<typeof browserModelSelectionPreparation>;

export const browserModelSelectionPreparationProjection = z
  .object({
    preparation: browserModelSelectionPreparation,
    evidence: browserApprovedModelEvidence,
  })
  .strict();

export const browserModelSelectionResultProjection = z
  .object({
    selection: browserModelSelectionTransition,
    invalidated_ruling_count: integer.min(0),
    terminalized_open_call_count: integer.min(0),
  })
  .strict();
export type BrowserModelSelectionResultProjection = z.infer<typeof browserModelSelectionResultProjection>;

function publicApproval(input: ModelSelectionCheckProjection['evidence']['approval']) {
  return browserApprovedModelEntry.parse({
    card_id: input.card_id,
    card_version: input.card_version,
    requested_id: input.requested_id,
    roles: input.roles,
    data_classes: input.data_classes,
    ...(input.re_confirmation_required === undefined
      ? {}
      : { re_confirmation_required: input.re_confirmation_required }),
  });
}

export function toBrowserApprovedModelEvidence(
  input: ModelSelectionCheckProjection['evidence'],
): BrowserApprovedModelEvidence {
  return browserApprovedModelEvidence.parse({
    approval: publicApproval(input.approval),
    effective_data_classes: input.effective_data_classes,
    card_status: input.card_status,
    signature_status: input.signature_status,
    integrity_alarm: input.integrity_alarm,
    current_card: input.current_card,
  });
}

export function toBrowserApprovedModels(input: unknown): BrowserApprovedModelsProjection {
  const parsed = approvedModelsProjection.parse(input);
  return browserApprovedModelsProjection.parse({
    mandate_id: parsed.mandate_id,
    mandate_version: parsed.mandate_version,
    mandate_state: parsed.mandate_state,
    default_acting_model: parsed.default_acting_model,
    models: parsed.models.map((model) => toBrowserApprovedModelEvidence(model)),
  });
}

function publicTransition(input: CurrentModelSelectionProjection['selection'] | ModelSelectionProjection['selection']) {
  if (input === null) return null;
  return browserModelSelectionTransition.parse({
    selection_id: input.selection_id,
    kind: input.kind,
    predecessor_selection_id: input.predecessor_selection_id,
    mandate_id: input.mandate_id,
    mandate_version: input.mandate_version,
    target: {
      card_id: input.target.card_id,
      card_version: input.target.card_version,
      requested_id: input.target.requested_id,
    },
    selected_at: input.selected_at,
    authority_effect: input.authority_effect,
  });
}

export function toBrowserCurrentModelSelection(input: unknown): BrowserCurrentModelSelectionProjection {
  const parsed = currentModelSelectionProjection.parse(input);
  if (parsed.state === 'unselected') return browserCurrentModelSelectionProjection.parse(parsed);
  return browserCurrentModelSelectionProjection.parse({
    state: 'selected',
    case_id: parsed.case_id,
    selection: publicTransition(parsed.selection),
    latest_observation:
      parsed.latest_observation === null
        ? null
        : {
            served_id: parsed.latest_observation.served_id,
            model_resolution: parsed.latest_observation.model_resolution,
            terminal_outcome: parsed.latest_observation.terminal_outcome,
            observed_at: parsed.latest_observation.observed_at,
          },
  });
}

export function toBrowserModelSelectionResult(input: unknown): BrowserModelSelectionResultProjection {
  const parsed = modelSelectionProjection.parse(input);
  return browserModelSelectionResultProjection.parse({
    selection: publicTransition(parsed.selection),
    invalidated_ruling_count: parsed.invalidated_ruling_count,
    terminalized_open_call_count: parsed.terminalized_open_call_count,
  });
}

interface PreparationRecord {
  readonly preparation_id: string;
  readonly session_id: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target: ModelSelectionTarget;
  readonly expected_current_selection_id: string | null;
  readonly authorization_boot_id: string;
  readonly authorization_check_id: string;
  readonly issued_at: string;
  readonly expires_at: string;
  state: 'issued' | 'consuming';
}

export interface BegunModelSelectionPreparation {
  readonly preparationId: string;
  readonly checkId: string;
  readonly expectedCurrentSelectionId: string | null;
  readonly target: ModelSelectionTarget;
}

export interface BrowserModelSelectionPreparationBinding {
  readonly target: ModelSelectionTarget;
  readonly expectedCurrentSelectionId: string | null;
}

export interface CaseModelSelectionPreparationStoreOptions {
  readonly ttlMs?: number;
  readonly now?: () => string;
  readonly nextPreparationId?: () => string;
}

export class CaseModelSelectionPreparationError extends Error {
  constructor(readonly code: 'authorization-boot-mismatch' | 'invalid-check-binding' | 'preparation-expired') {
    super(code);
    this.name = 'CaseModelSelectionPreparationError';
  }
}

export class CaseModelSelectionPreparationStore {
  readonly #records = new Map<string, PreparationRecord>();
  readonly #currentBySession = new Map<string, string>();
  readonly #ttlMs: number;
  readonly #now: () => string;
  readonly #nextPreparationId: () => string;

  constructor(options: CaseModelSelectionPreparationStoreOptions = {}) {
    this.#ttlMs = options.ttlMs ?? MAX_BROWSER_PREPARATION_TTL_MS;
    if (!Number.isInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > MAX_BROWSER_PREPARATION_TTL_MS) {
      throw new RangeError('browser model-selection preparation TTL must be from 1 through 120000 milliseconds');
    }
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#nextPreparationId =
      options.nextPreparationId ?? (() => `msp_${randomBytes(16).toString('hex')}`);
  }

  #delete(preparationId: string): void {
    const record = this.#records.get(preparationId);
    if (record === undefined) return;
    this.#records.delete(preparationId);
    if (this.#currentBySession.get(record.session_id) === preparationId) {
      this.#currentBySession.delete(record.session_id);
    }
  }

  #expire(at: string): void {
    for (const [preparationId, record] of this.#records) {
      if (record.expires_at <= at) this.#delete(preparationId);
    }
  }

  create(
    session: CaseSessionRecord,
    input: ModelSelectionCheckProjection,
    bindingInput: BrowserModelSelectionPreparationBinding,
  ): BrowserModelSelectionPreparation {
    const checkProjection = modelSelectionCheckProjection.parse(input);
    const check = checkProjection.check;
    const binding = {
      target: modelSelectionTarget.parse(bindingInput.target),
      expectedCurrentSelectionId:
        bindingInput.expectedCurrentSelectionId === null ? null : id.parse(bindingInput.expectedCurrentSelectionId),
    };
    const at = timestamp.parse(this.#now());
    this.#expire(at);
    if (check.authorization_boot_id !== session.authorization_boot_id) {
      throw new CaseModelSelectionPreparationError('authorization-boot-mismatch');
    }
    if (
      session.state !== 'active' ||
      session.role !== 'case_officer' ||
      session.expires_at <= at ||
      check.state !== 'issued' ||
      check.authenticated_actor !== 'proc:orchestrator' ||
      check.world_id !== session.world_id ||
      check.case_id !== session.case_id ||
      check.expected_current_selection_id !== binding.expectedCurrentSelectionId ||
      check.expires_at <= at ||
      check.target.card_id !== binding.target.card_id ||
      check.target.card_version !== binding.target.card_version ||
      check.target.requested_id !== binding.target.requested_id ||
      check.target.card_id !== checkProjection.evidence.approval.card_id ||
      check.target.card_version !== checkProjection.evidence.approval.card_version ||
      check.target.requested_id !== checkProjection.evidence.approval.requested_id
    ) {
      throw new CaseModelSelectionPreparationError('invalid-check-binding');
    }
    const previous = this.#currentBySession.get(session.session_id);
    if (previous !== undefined) this.#delete(previous);
    const preparationId = id.parse(this.#nextPreparationId());
    if (this.#records.has(preparationId)) throw new Error('browser preparation id source repeated a value');
    const expiresAt = timestamp.parse(
      new Date(
        Math.min(
          Date.parse(at) + this.#ttlMs,
          Date.parse(session.expires_at),
          Date.parse(check.expires_at),
        ),
      ).toISOString(),
    );
    if (expiresAt <= at) throw new CaseModelSelectionPreparationError('preparation-expired');
    const record: PreparationRecord = {
      preparation_id: preparationId,
      session_id: session.session_id,
      role: session.role,
      world_id: session.world_id,
      case_id: session.case_id,
      target: {
        card_id: check.target.card_id,
        card_version: check.target.card_version,
        requested_id: check.target.requested_id,
      },
      expected_current_selection_id: check.expected_current_selection_id,
      authorization_boot_id: check.authorization_boot_id,
      authorization_check_id: check.check_id,
      issued_at: at,
      expires_at: expiresAt,
      state: 'issued',
    };
    this.#records.set(preparationId, record);
    this.#currentBySession.set(session.session_id, preparationId);
    return browserModelSelectionPreparation.parse({
      preparation_id: preparationId,
      target: record.target,
      issued_at: at,
      expires_at: expiresAt,
    });
  }

  beginUse(preparationIdInput: string, session: CaseSessionRecord): BegunModelSelectionPreparation | null {
    const preparationId = id.parse(preparationIdInput);
    const at = timestamp.parse(this.#now());
    this.#expire(at);
    const record = this.#records.get(preparationId);
    if (
      record === undefined ||
      record.state !== 'issued' ||
      record.session_id !== session.session_id ||
      record.role !== session.role ||
      record.world_id !== session.world_id ||
      record.case_id !== session.case_id ||
      record.authorization_boot_id !== session.authorization_boot_id ||
      record.expires_at <= at
    ) {
      return null;
    }
    record.state = 'consuming';
    return {
      preparationId,
      checkId: record.authorization_check_id,
      expectedCurrentSelectionId: record.expected_current_selection_id,
      target: record.target,
    };
  }

  burn(preparationIdInput: string): void {
    const parsed = id.safeParse(preparationIdInput);
    if (parsed.success) this.#delete(parsed.data);
  }

  burnForSession(sessionIdInput: string): void {
    const sessionId = id.parse(sessionIdInput);
    const current = this.#currentBySession.get(sessionId);
    if (current !== undefined) this.#delete(current);
  }

  burnForCase(worldIdInput: string, caseIdInput: string): void {
    for (const [preparationId, record] of this.#records) {
      if (record.world_id === worldIdInput && record.case_id === caseIdInput) this.#delete(preparationId);
    }
  }

  burnStaleForCase(worldIdInput: string, caseIdInput: string, currentSelectionId: string | null): void {
    for (const [preparationId, record] of this.#records) {
      if (
        record.world_id === worldIdInput &&
        record.case_id === caseIdInput &&
        record.expected_current_selection_id !== currentSelectionId
      ) {
        this.#delete(preparationId);
      }
    }
  }

  activeCount(): number {
    this.#expire(timestamp.parse(this.#now()));
    return this.#records.size;
  }
}
