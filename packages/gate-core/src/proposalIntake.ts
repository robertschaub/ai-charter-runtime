// SPDX-License-Identifier: AGPL-3.0-only
/** M5.11 authorization-owned proposal-purpose currentness and single-use intake. */
import { randomBytes } from 'node:crypto';

import { canonicalize } from './canonicalize.js';
import { CardRegistry, type CardInspection } from './cardRegistry.js';
import { projectConversation } from './conversationProjection.js';
import { digestFor, sha256Hex, verifyDigest } from './hash.js';
import { verifyEmbeddedMac, type Keyring } from './keyring.js';
import { digestModelOutput } from './modelOutputAdmission.js';
import {
  id,
  modelCallOpenRecord,
  proposalCallBinding,
  proposalDraft,
  proposalIntakeConsumeResult,
  proposalIntakeRecord,
  proposalIntakeReference,
  proposalIntakeStatusProjection,
  proposalOriginRecord,
  proposalRevisionCallBinding,
  proposalRevisionPreparationProjection,
  proposalRevisionPreparationRecord,
  proposalRevisionSourceProjection,
  proposalRunProcessProjection,
  timestamp,
  type ModelCallOpenRecord,
  type ModelOutputAdmission,
  type ProposalCallBinding,
  type ProposalDraft,
  type ProposalIntakeConsumeResult,
  type ProposalIntakeRecord,
  type ProposalIntakeStatusProjection,
  type ProposalRunProcessProjection,
  type ProposalRevisionCallBinding,
  type ProposalRevisionPreparationRecord,
  type ProposalRevisionPreparationProjection,
  type ProposalRevisionSourceProjection,
  type WalOp,
} from './schemas/index.js';
import { freezeProposal } from './authorizationCore.js';
import {
  mandateVersionKey,
  proposalRevisionPreparationBlocksReplacement,
  type WorldState,
} from './state.js';
import { SystemUseDecisionService } from './systemUseDecision.js';
import { WalStore, type TransactionActor } from './walStore.js';

const MAX_PROPOSAL_BYTES = 32_768;

const scalarSchema = { oneOf: [{ type: 'string' }, { type: 'integer' }, { type: 'boolean' }, { type: 'null' }] } as const;
export const PROPOSAL_DRAFT_JSON_SCHEMA = Object.freeze({
  type: 'object',
  additionalProperties: false,
  required: [
    'declared_objective',
    'proposed_action',
    'target',
    'exact_parameters',
    'material_input_ids',
    'derived_claim_ids',
    'data_to_be_disclosed',
    'cost_obligation',
    'material_consequences',
    'reversibility_class',
    'commercial_influence',
  ],
  properties: {
    declared_objective: { type: 'string', minLength: 1, maxLength: 4096 },
    proposed_action: { type: 'string', minLength: 1, maxLength: 4096 },
    target: {
      type: 'object',
      additionalProperties: false,
      required: ['recipient', 'resource'],
      properties: { recipient: { type: 'string', maxLength: 4096 }, resource: { type: 'string', maxLength: 4096 } },
    },
    exact_parameters: {
      type: 'object',
      maxProperties: 64,
      additionalProperties: { oneOf: [scalarSchema, { type: 'array', maxItems: 64, items: scalarSchema }] },
    },
    material_input_ids: { type: 'array', maxItems: 128, uniqueItems: true, items: { type: 'string' } },
    derived_claim_ids: { type: 'array', maxItems: 128, uniqueItems: true, items: { type: 'string' } },
    data_to_be_disclosed: { type: 'array', maxItems: 64, items: { type: 'string', minLength: 1, maxLength: 4096 } },
    cost_obligation: {
      type: 'object',
      additionalProperties: false,
      required: ['amount_minor_units', 'description'],
      properties: { amount_minor_units: { type: 'integer', minimum: 0 }, description: { type: 'string', maxLength: 4096 } },
    },
    material_consequences: { type: 'array', maxItems: 64, items: { type: 'string', minLength: 1, maxLength: 4096 } },
    reversibility_class: { type: 'string', pattern: '^[a-z][a-z0-9-]*$' },
    commercial_influence: {
      type: 'object',
      additionalProperties: false,
      required: ['applicable', 'note'],
      properties: { applicable: { type: 'boolean' }, note: { type: 'string', maxLength: 4096 } },
    },
  },
});

export const PROPOSAL_DRAFT_SCHEMA_DIGEST = sha256Hex(canonicalize(PROPOSAL_DRAFT_JSON_SCHEMA));
export const PROPOSAL_DRAFT_RESPONSE_FORMAT = Object.freeze({
  type: 'json_schema',
  json_schema: {
    name: 'proposal_draft_v1',
    strict: true,
    schema: PROPOSAL_DRAFT_JSON_SCHEMA,
  },
});

export const PROPOSAL_DRAFT_SYSTEM_INSTRUCTION = [
  'Return exactly one proposal-draft@1 JSON object matching the supplied native schema.',
  'Propose semantics only. Use only the opaque evidence item ids present in the projection.',
  'Do not claim authority, permission, approval, provenance, classification, service, action class, or gate outcome.',
].join(' ');

export const PROPOSAL_REVISION_SYSTEM_INSTRUCTION = [
  'Return exactly one proposal-draft@1 JSON object matching the supplied native schema for proposal-revision@1.',
  'Revise semantics only from the refreshed projection and semantic source proposal.',
  'Use only opaque evidence item ids present in the refreshed projection.',
  'Do not claim authority, permission, approval, provenance, classification, lineage, service, action class, or gate outcome.',
].join(' ');

export class ProposalIntakeError extends Error {
  constructor(
    readonly code: 'forbidden' | 'not-found' | 'conflict' | 'currentness' | 'invalid-content',
    message: string,
  ) {
    super(message);
    this.name = 'ProposalIntakeError';
  }
}

interface ProposalGovernance {
  readonly selection: WorldState['modelSelections'] extends Map<string, infer T> ? T : never;
  readonly mandate: WorldState['mandates'] extends Map<string, infer T> ? T : never;
  readonly inspection: CardInspection;
}

export interface ProposalIntakeServiceOptions {
  readonly store: WalStore;
  readonly cards: CardRegistry;
  readonly keyring: Keyring;
  readonly systemUse: SystemUseDecisionService;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly intakeTtlMs?: number;
  readonly now?: () => string;
  readonly nextIntakeId?: () => string;
  readonly nextProposalId?: () => string;
  readonly nextActionId?: () => string;
  readonly nextRevisionPreparationId?: () => string;
  readonly nextRevisionRunId?: () => string;
}

export type PreparedProposalIntake = {
  readonly op: Extract<WalOp, { op: 'proposal_intake.issue' }>;
  readonly reference: ReturnType<typeof proposalIntakeReference.parse>;
};

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function hasWellFormedUnicodeStrings(value: unknown): boolean {
  if (typeof value === 'string') return isWellFormedUnicode(value);
  if (Array.isArray(value)) return value.every(hasWellFormedUnicodeStrings);
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).every(([key, entry]) => isWellFormedUnicode(key) && hasWellFormedUnicodeStrings(entry));
  }
  return true;
}

/** Validate JSON grammar while retaining each object's key set; JSON.parse alone accepts duplicate keys. */
function assertNoDuplicateJsonKeys(content: string): void {
  let cursor = 0;
  const whitespace = () => { while (/\s/u.test(content[cursor] ?? '')) cursor += 1; };
  const stringValue = (): string => {
    const start = cursor;
    if (content[cursor] !== '"') throw new Error('expected string');
    cursor += 1;
    while (cursor < content.length) {
      const current = content[cursor];
      if (current === '"') {
        cursor += 1;
        return JSON.parse(content.slice(start, cursor)) as string;
      }
      if (current === '\\') {
        cursor += 1;
        if (content[cursor] === 'u') cursor += 4;
      }
      cursor += 1;
    }
    throw new Error('unterminated string');
  };
  const value = (): void => {
    whitespace();
    const current = content[cursor];
    if (current === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set<string>();
      if (content[cursor] === '}') { cursor += 1; return; }
      while (true) {
        whitespace();
        const key = stringValue();
        if (keys.has(key)) throw new Error('duplicate key');
        keys.add(key);
        whitespace();
        if (content[cursor] !== ':') throw new Error('expected colon');
        cursor += 1;
        value();
        whitespace();
        if (content[cursor] === '}') { cursor += 1; return; }
        if (content[cursor] !== ',') throw new Error('expected comma');
        cursor += 1;
      }
    }
    if (current === '[') {
      cursor += 1;
      whitespace();
      if (content[cursor] === ']') { cursor += 1; return; }
      while (true) {
        value();
        whitespace();
        if (content[cursor] === ']') { cursor += 1; return; }
        if (content[cursor] !== ',') throw new Error('expected comma');
        cursor += 1;
      }
    }
    if (current === '"') { void stringValue(); return; }
    const tail = content.slice(cursor);
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(tail)?.[0];
    if (token === undefined) throw new Error('invalid token');
    cursor += token.length;
  };
  value();
  whitespace();
  if (cursor !== content.length) throw new Error('trailing data');
}

export function parseProposalDraft(content: string): ProposalDraft {
  const bytes = Buffer.from(content, 'utf8');
  if (bytes.byteLength > MAX_PROPOSAL_BYTES || !isWellFormedUnicode(content)) {
    throw new ProposalIntakeError('invalid-content', 'proposal draft is outside its byte or Unicode bounds');
  }
  try {
    assertNoDuplicateJsonKeys(content);
    const parsed = JSON.parse(content) as unknown;
    if (!hasWellFormedUnicodeStrings(parsed)) {
      throw new ProposalIntakeError('invalid-content', 'proposal draft contains ill-formed Unicode');
    }
    return proposalDraft.parse(parsed);
  } catch (error) {
    if (error instanceof ProposalIntakeError) throw error;
    throw new ProposalIntakeError('invalid-content', 'proposal draft does not satisfy proposal-draft@1');
  }
}

export class ProposalIntakeService {
  readonly #store: WalStore;
  readonly #cards: CardRegistry;
  readonly #keyring: Keyring;
  readonly #systemUse: SystemUseDecisionService;
  readonly #caseId: string;
  readonly #authorizationBootId: string;
  readonly #intakeTtlMs: number;
  readonly #now: () => string;
  readonly #nextIntakeId: () => string;
  readonly #nextProposalId: () => string;
  readonly #nextActionId: () => string;
  readonly #nextRevisionPreparationId: () => string;
  readonly #nextRevisionRunId: () => string;

  constructor(options: ProposalIntakeServiceOptions) {
    this.#store = options.store;
    this.#cards = options.cards;
    this.#keyring = options.keyring;
    this.#systemUse = options.systemUse;
    this.#caseId = id.parse(options.caseId);
    this.#authorizationBootId = id.parse(options.authorizationBootId);
    this.#intakeTtlMs = options.intakeTtlMs ?? 120_000;
    if (!Number.isInteger(this.#intakeTtlMs) || this.#intakeTtlMs < 1 || this.#intakeTtlMs > 120_000) {
      throw new RangeError('proposal intake TTL must be from 1 through 120000 milliseconds');
    }
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#nextIntakeId = options.nextIntakeId ?? (() => `pint_${randomBytes(16).toString('hex')}`);
    this.#nextProposalId = options.nextProposalId ?? (() => `prp_${randomBytes(16).toString('hex')}`);
    this.#nextActionId = options.nextActionId ?? (() => `act_${randomBytes(16).toString('hex')}`);
    this.#nextRevisionPreparationId =
      options.nextRevisionPreparationId ?? (() => `rprep_${randomBytes(16).toString('hex')}`);
    this.#nextRevisionRunId = options.nextRevisionRunId ?? (() => `prun_${randomBytes(16).toString('hex')}`);
  }

  #requireOrchestrator(actor: TransactionActor): void {
    if (actor.credential !== 'proc:orchestrator') {
      throw new ProposalIntakeError('forbidden', 'only the orchestrator process may use proposal intake');
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
      throw new ProposalIntakeError('currentness', 'case-session provenance is unavailable');
    }
    return receipt;
  }

  #governance(state: WorldState, at: string): ProposalGovernance {
    const selectionId = state.currentModelSelectionByCase.get(this.#caseId);
    const selection = selectionId === undefined ? undefined : state.modelSelections.get(selectionId);
    if (selection === undefined || selection.case_id !== this.#caseId) {
      throw new ProposalIntakeError('currentness', 'current model selection is unavailable');
    }
    const status = state.mandateStatus.get(selection.mandate_id);
    const mandate = status === undefined ? undefined : state.mandates.get(mandateVersionKey(selection.mandate_id, status.version));
    if (
      status?.state !== 'active' ||
      mandate === undefined ||
      mandate.version !== selection.mandate_version ||
      mandate.state !== 'active' ||
      at < mandate.issued_at ||
      at > mandate.expires_at ||
      at < mandate.limits.time_window.not_before ||
      at > mandate.limits.time_window.not_after ||
      verifyEmbeddedMac(this.#keyring, 'mandate-binding', mandate as unknown as Record<string, unknown>, 'binding') !== 'valid'
    ) {
      throw new ProposalIntakeError('currentness', 'current mandate is unavailable');
    }
    const approval = mandate.approved_models.find((candidate) =>
      candidate.card_id === selection.target.card_id &&
      candidate.card_version === selection.target.card_version &&
      candidate.requested_id === selection.target.requested_id &&
      candidate.roles.includes('acting'));
    const inspection = this.#cards.get(selection.target.card_id);
    const responseFormat = inspection?.card.capabilities.response_format;
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
      responseFormat === undefined ||
      responseFormat.provenance !== 'probe-tested' ||
      !responseFormat.value.includes('json_schema') ||
      state.policy === undefined ||
      canonicalize(this.#systemUse.resolve(state, mandate, state.policy.policy_version, at)) !== canonicalize(selection.system_use_decision)
    ) {
      throw new ProposalIntakeError('currentness', 'selected model proposal governance is unavailable or changed');
    }
    return { selection, mandate, inspection };
  }

  #projection(state: WorldState, governance: ProposalGovernance) {
    const approval = governance.mandate.approved_models.find((candidate) =>
      candidate.card_id === governance.selection.target.card_id &&
      candidate.card_version === governance.selection.target.card_version &&
      candidate.requested_id === governance.selection.target.requested_id &&
      candidate.roles.includes('acting'))!;
    return projectConversation({
      worldId: state.worldId,
      caseId: this.#caseId,
      provider: approval.card_id,
      role: 'acting',
      mandateClearances: approval.data_classes.acting ?? [],
      cardClearances: governance.inspection.card.declared_data_classes.acting ?? [],
      entries: [...state.storeItems.values()],
    });
  }

  #revisionSourceProjection(source: WorldState['proposals'] extends Map<string, infer T> ? T : never): ProposalRevisionSourceProjection {
    return proposalRevisionSourceProjection.parse({
      declared_objective: source.declared_objective,
      proposed_action: source.proposed_action,
      target: { recipient: source.target.recipient, resource: source.target.resource },
      exact_parameters: Object.fromEntries(
        Object.entries(source.exact_parameters).map(([key, value]) => [key, Array.isArray(value) ? [...value] : value]),
      ),
      data_to_be_disclosed: [...source.data_to_be_disclosed],
      cost_obligation: {
        amount_minor_units: source.cost_obligation.amount_minor_units,
        description: source.cost_obligation.description,
      },
      material_consequences: [...source.material_consequences],
      reversibility_class: source.reversibility_class,
      commercial_influence: {
        applicable: source.commercial_influence.applicable,
        note: source.commercial_influence.note,
      },
      basis: [
        ...source.material_inputs.map((item) => ({ standing: item.store as 'said' | 'confirmed', text: item.text })),
        ...source.derived_claims.map((item) => ({ standing: 'inferred-unconfirmed' as const, text: item.text })),
      ],
    });
  }

  #revisionProjection(preparation: ProposalRevisionPreparationRecord): ProposalRevisionPreparationProjection {
    return proposalRevisionPreparationProjection.parse({
      kind: 'proposal_revision_preparation',
      preparation_id: preparation.preparation_id,
      proposal_run_id: preparation.proposal_run_id,
      source_proposal_run_id: preparation.source_proposal_run_id,
      target: {
        card_id: preparation.card_id,
        card_version: preparation.card_version,
        requested_id: preparation.requested_id,
      },
      issued_at: preparation.issued_at,
      expires_at: preparation.expires_at,
    });
  }

  hasLiveRevisionAttempt(state: WorldState, sourceProposalIdInput: string, atInput = this.#now()): boolean {
    const sourceProposalId = id.parse(sourceProposalIdInput);
    const at = timestamp.parse(atInput);
    return [...state.proposalRevisionPreparations.values()].some(
      (preparation) =>
        preparation.source_proposal_id === sourceProposalId &&
        proposalRevisionPreparationBlocksReplacement(state, preparation, at),
    );
  }

  #assertRevisionPreparationCurrent(
    state: WorldState,
    at: string,
    preparationInput: ProposalRevisionPreparationRecord,
    sessionIdInput: string,
    projectionInput?: ReturnType<typeof projectConversation>,
  ): { preparation: ProposalRevisionPreparationRecord; source: WorldState['proposals'] extends Map<string, infer T> ? T : never; projection: ReturnType<typeof projectConversation> } {
    const preparation = proposalRevisionPreparationRecord.parse(preparationInput);
    const sessionId = id.parse(sessionIdInput);
    if (
      !['issued', 'consumed'].includes(preparation.state) ||
      preparation.authorization_boot_id !== this.#authorizationBootId ||
      preparation.case_id !== this.#caseId ||
      preparation.session_id !== sessionId ||
      at >= preparation.expires_at ||
      preparation.purpose !== 'proposal-revision@1' ||
      preparation.proposal_schema_digest !== PROPOSAL_DRAFT_SCHEMA_DIGEST
    ) throw new ProposalIntakeError('currentness', 'proposal revision preparation is unavailable');
    this.#receipt(state, sessionId, at);
    const source = state.proposals.get(preparation.source_proposal_id);
    const sourceOrigin = state.proposalOrigins.get(preparation.source_proposal_id);
    const ruling = state.rulings.get(preparation.source_ruling_id);
    const escalation = state.escalations.get(preparation.source_escalation_id);
    const response = state.actionRecords.find((entry) => entry.entry_id === preparation.response_record_entry_id);
    const responseEvent = response?.human_intervention_event;
    const responsePayload = responseEvent?.event === 'human_intervention_event' ? responseEvent.payload : undefined;
    const latestRevision = source === undefined
      ? 0
      : Math.max(...[...state.proposals.values()].filter((candidate) => candidate.action_id === source.action_id).map((candidate) => candidate.revision));
    if (
      source === undefined ||
      sourceOrigin === undefined ||
      sourceOrigin.proposal_run_id !== preparation.source_proposal_run_id ||
      source.proposal_hash !== preparation.source_proposal_hash ||
      source.action_id !== preparation.action_id ||
      source.revision !== preparation.source_revision ||
      preparation.expected_revision !== latestRevision + 1 ||
      ruling === undefined ||
      ruling.gate !== 'verify' ||
      ruling.verdict !== 'escalate' ||
      ruling.binding.frozen_proposal_hash !== source.proposal_hash ||
      ruling.successor_ruling_id !== null ||
      escalation === undefined ||
      escalation.ruling_id !== ruling.ruling_id ||
      escalation.state !== 'disposed' ||
      escalation.successor_ruling_id !== null ||
      escalation.dialogue_item_ref !== preparation.dialogue_item_ref ||
      escalation.terminal_disposition !== preparation.disposition ||
      responseEvent?.escalation_id !== escalation.escalation_id ||
      responsePayload?.kind !== 'dialogue_response_recorded' ||
      responsePayload.disposition !== preparation.disposition ||
      responsePayload.scope?.item_ref !== preparation.dialogue_item_ref ||
      !['confirm', 'correct', 'narrow'].includes(responsePayload.disposition) ||
      (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== preparation.conversation_version
    ) throw new ProposalIntakeError('currentness', 'proposal revision lineage is unavailable or already continued');
    const governance = this.#governance(state, at);
    const projection = this.#projection(state, governance);
    if (
      governance.selection.selection_id !== preparation.selection_id ||
      governance.mandate.mandate_id !== preparation.mandate_id ||
      governance.mandate.version !== preparation.mandate_version ||
      governance.inspection.card.card_id !== preparation.card_id ||
      governance.inspection.card.card_version !== preparation.card_version ||
      !verifyDigest(governance.inspection.digest, preparation.card_digest) ||
      governance.inspection.keyId !== preparation.verifying_key_id ||
      governance.selection.target.requested_id !== preparation.requested_id ||
      governance.mandate.connected_service !== preparation.service ||
      governance.mandate.action_class !== preparation.action_class ||
      canonicalize(governance.selection.system_use_decision) !== canonicalize(preparation.system_use_decision) ||
      state.policy === undefined ||
      state.policy.policy_version !== preparation.policy_version ||
      !verifyDigest(state.policy.policy_content_digest, preparation.policy_content_digest) ||
      state.policy.evaluator_build_id !== preparation.evaluator_build_id ||
      !this.#systemUse.isReferenceCurrent(state, preparation.system_use_decision, at) ||
      projection.items.length === 0 ||
      canonicalize(projection.items.map((item) => item.id)) !== canonicalize(preparation.projection_item_ids) ||
      !verifyDigest(digestFor('conversation-projection', projection), preparation.projection_digest) ||
      (projectionInput !== undefined && canonicalize(projectionInput) !== canonicalize(projection))
    ) throw new ProposalIntakeError('currentness', 'proposal revision governance or projection changed');
    return { preparation, source, projection };
  }

  async prepareRevision(
    caseIdInput: string,
    sourceRunIdInput: string,
    sessionIdInput: string,
    actor: TransactionActor,
  ): Promise<ProposalRevisionPreparationProjection> {
    this.#requireOrchestrator(actor);
    const caseId = id.parse(caseIdInput);
    const sourceRunId = id.parse(sourceRunIdInput);
    const sessionId = id.parse(sessionIdInput);
    if (caseId !== this.#caseId) throw new ProposalIntakeError('not-found', 'proposal run does not exist for this case');
    const completed = await this.#store.transactWithState<ProposalRevisionPreparationProjection>(
      'proposal_revision_prepare',
      actor,
      (state, at) => {
        this.#receipt(state, sessionId, at);
        const sourceIntakeId = state.proposalIntakeByRun.get(sourceRunId);
        const sourceIntake = sourceIntakeId === undefined ? undefined : state.proposalIntakes.get(sourceIntakeId);
        const source = sourceIntake?.proposal_id === null || sourceIntake?.proposal_id === undefined
          ? undefined
          : state.proposals.get(sourceIntake.proposal_id);
        const sourceOrigin = source === undefined ? undefined : state.proposalOrigins.get(source.proposal_id);
        if (sourceIntake?.case_id !== this.#caseId || source === undefined || sourceOrigin === undefined) {
          throw new ProposalIntakeError('not-found', 'proposal run does not have a frozen proposal');
        }
        const ruling = [...state.rulings.values()]
          .filter((candidate) =>
            candidate.gate === 'verify' &&
            candidate.verdict === 'escalate' &&
            candidate.binding.frozen_proposal_hash === source.proposal_hash)
          .sort((left, right) => right.issued_at.localeCompare(left.issued_at))[0];
        const escalation = ruling === undefined
          ? undefined
          : [...state.escalations.values()].find((candidate) => candidate.ruling_id === ruling.ruling_id);
        const response = escalation === undefined
          ? undefined
          : [...state.actionRecords]
              .reverse()
              .find((entry) =>
                entry.human_intervention_event?.escalation_id === escalation.escalation_id &&
                entry.human_intervention_event.event === 'human_intervention_event' &&
                entry.human_intervention_event.payload.kind === 'dialogue_response_recorded');
        const responseEvent = response?.human_intervention_event;
        const payload = responseEvent?.event === 'human_intervention_event' ? responseEvent.payload : undefined;
        if (
          ruling === undefined ||
          escalation === undefined ||
          response === undefined ||
          escalation.state !== 'disposed' ||
          escalation.dialogue_item_ref === null ||
          escalation.successor_ruling_id !== null ||
          ruling.successor_ruling_id !== null ||
          payload?.kind !== 'dialogue_response_recorded' ||
          !['confirm', 'correct', 'narrow'].includes(payload.disposition) ||
          payload.scope?.item_ref !== escalation.dialogue_item_ref
        ) throw new ProposalIntakeError('currentness', 'proposal run has no eligible dialogue continuation');
        const governance = this.#governance(state, at);
        const projection = this.#projection(state, governance);
        const conversationVersion = state.conversationVersionByCase.get(this.#caseId) ?? 0;
        if (projection.items.length === 0 || conversationVersion < 1) {
          throw new ProposalIntakeError('currentness', 'proposal revision projection is unavailable');
        }
        const expectedRevision = Math.max(
          ...[...state.proposals.values()]
            .filter((candidate) => candidate.action_id === source.action_id)
            .map((candidate) => candidate.revision),
        ) + 1;
        const sameTuple = [...state.proposalRevisionPreparations.values()].filter(
          (candidate) =>
            candidate.source_proposal_id === source.proposal_id &&
            candidate.response_record_entry_id === response.entry_id &&
            candidate.action_id === source.action_id &&
            candidate.conversation_version === conversationVersion &&
            candidate.projection_digest === digestFor('conversation-projection', projection),
        );
        const issued = sameTuple.find((candidate) => candidate.state === 'issued' && at < candidate.expires_at);
        if (issued !== undefined) {
          if (issued.session_id !== sessionId) {
            throw new ProposalIntakeError('conflict', 'another session owns the live revision preparation');
          }
          this.#assertRevisionPreparationCurrent(state, at, issued, sessionId, projection);
          return { ops: [], result: this.#revisionProjection(issued) };
        }
        const blockingConsumed = sameTuple.find((candidate) =>
          candidate.state === 'consumed' && proposalRevisionPreparationBlocksReplacement(state, candidate, at));
        if (blockingConsumed !== undefined) {
          throw new ProposalIntakeError('conflict', 'the dialogue continuation already has a live revision run');
        }
        const preparationId = id.parse(this.#nextRevisionPreparationId());
        const proposalRunId = id.parse(this.#nextRevisionRunId());
        const expiresAt = timestamp.parse(new Date(Math.min(Date.parse(at) + 120_000, Date.parse(this.#receipt(state, sessionId, at).expires_at))).toISOString());
        const preparation = proposalRevisionPreparationRecord.parse({
          world_id: state.worldId,
          preparation_id: preparationId,
          proposal_run_id: proposalRunId,
          authorization_boot_id: this.#authorizationBootId,
          case_id: this.#caseId,
          session_id: sessionId,
          source_proposal_run_id: sourceRunId,
          source_proposal_id: source.proposal_id,
          source_proposal_hash: source.proposal_hash,
          action_id: source.action_id,
          source_revision: source.revision,
          expected_revision: expectedRevision,
          source_ruling_id: ruling.ruling_id,
          source_escalation_id: escalation.escalation_id,
          dialogue_item_ref: escalation.dialogue_item_ref,
          disposition: payload!.disposition,
          response_record_entry_id: response!.entry_id,
          conversation_version: conversationVersion,
          projection_digest: digestFor('conversation-projection', projection),
          projection_item_ids: projection.items.map((item) => item.id),
          selection_id: governance.selection.selection_id,
          mandate_id: governance.mandate.mandate_id,
          mandate_version: governance.mandate.version,
          card_id: governance.inspection.card.card_id,
          card_version: governance.inspection.card.card_version,
          card_digest: governance.inspection.digest,
          verifying_key_id: governance.inspection.keyId,
          requested_id: governance.selection.target.requested_id,
          system_use_decision: governance.selection.system_use_decision,
          policy_version: state.policy!.policy_version,
          policy_content_digest: state.policy!.policy_content_digest,
          evaluator_build_id: state.policy!.evaluator_build_id,
          service: governance.mandate.connected_service,
          action_class: governance.mandate.action_class,
          purpose: 'proposal-revision@1',
          proposal_schema_digest: PROPOSAL_DRAFT_SCHEMA_DIGEST,
          issued_at: at,
          expires_at: expiresAt,
          state: 'issued',
          state_changed_at: at,
          consumed_call_id: null,
          invalidation_reason: null,
        });
        return {
          ops: [{ op: 'proposal_revision_preparation.issue', preparation }],
          result: this.#revisionProjection(preparation),
        };
      },
    );
    return completed.result;
  }

  prepareRevisionCall(
    state: WorldState,
    at: string,
    bindingInput: ProposalRevisionCallBinding,
    sessionIdInput: string,
    projectionInput: ReturnType<typeof projectConversation>,
    callIdInput: string,
  ): { op: Extract<WalOp, { op: 'proposal_revision_preparation.consume' }>; source: ProposalRevisionSourceProjection } {
    const binding = proposalRevisionCallBinding.parse(bindingInput);
    const preparation = state.proposalRevisionPreparations.get(binding.preparation_id);
    if (preparation === undefined || preparation.state !== 'issued') {
      throw new ProposalIntakeError('currentness', 'proposal revision preparation is not issued');
    }
    const current = this.#assertRevisionPreparationCurrent(state, at, preparation, sessionIdInput, projectionInput);
    return {
      op: {
        op: 'proposal_revision_preparation.consume',
        preparation_id: preparation.preparation_id,
        call_id: id.parse(callIdInput),
        changed_at: at,
      },
      source: this.#revisionSourceProjection(current.source),
    };
  }

  assertCallBinding(
    state: WorldState,
    at: string,
    bindingInput: ProposalCallBinding,
    sessionIdInput: string,
    projectionInput: ReturnType<typeof projectConversation>,
  ): void {
    const binding = proposalCallBinding.parse(bindingInput);
    this.#receipt(state, sessionIdInput, at);
    const governance = this.#governance(state, at);
    const projection = this.#projection(state, governance);
    if (
      binding.proposal_schema_digest !== PROPOSAL_DRAFT_SCHEMA_DIGEST ||
      binding.conversation_version !== (state.conversationVersionByCase.get(this.#caseId) ?? 0) ||
      projection.items.length === 0 ||
      canonicalize(projection) !== canonicalize(projectionInput)
    ) {
      throw new ProposalIntakeError('currentness', 'proposal-purpose binding is unavailable or stale');
    }
  }

  prepareIntake(
    state: WorldState,
    at: string,
    callInput: ModelCallOpenRecord,
    decision: Extract<ModelOutputAdmission, { readonly disposition: 'admitted' }>,
  ): PreparedProposalIntake {
    const call = modelCallOpenRecord.parse(callInput);
    if (
      (call.proposal_binding === null) === (call.revision_binding === null) ||
      call.ingress_binding !== null ||
      call.session_id === null
    ) {
      throw new ProposalIntakeError('currentness', 'only a proposal-purpose call can receive a proposal intake');
    }
    const governance = this.#governance(state, at);
    const projection = this.#projection(state, governance);
    let proposalRunId: string;
    let conversationVersion: number;
    let proposalSchemaDigest: string;
    let revisionPreparationId: string | null = null;
    if (call.proposal_binding !== null) {
      this.assertCallBinding(state, at, call.proposal_binding, call.session_id, projection);
      proposalRunId = call.proposal_binding.proposal_run_id;
      conversationVersion = call.proposal_binding.conversation_version;
      proposalSchemaDigest = call.proposal_binding.proposal_schema_digest;
    } else {
      const revision = call.revision_binding === null
        ? undefined
        : state.proposalRevisionPreparations.get(call.revision_binding.preparation_id);
      if (revision === undefined || revision.consumed_call_id !== call.call_id) {
        throw new ProposalIntakeError('currentness', 'proposal revision call lost its preparation');
      }
      this.#assertRevisionPreparationCurrent(state, at, revision, call.session_id, projection);
      proposalRunId = revision.proposal_run_id;
      conversationVersion = revision.conversation_version;
      proposalSchemaDigest = revision.proposal_schema_digest;
      revisionPreparationId = revision.preparation_id;
    }
    if (
      governance.selection.selection_id !== call.selection_id ||
      canonicalize(call.projection_item_ids) !== canonicalize(projection.items.map((item) => item.id)) ||
      !verifyDigest(call.projection_digest, digestFor('conversation-projection', projection))
    ) {
      throw new ProposalIntakeError('currentness', 'proposal intake call binding is no longer current');
    }
    const intakeId = id.parse(this.#nextIntakeId());
    const expiresAt = timestamp.parse(new Date(Date.parse(at) + this.#intakeTtlMs).toISOString());
    const intake = proposalIntakeRecord.parse({
      world_id: state.worldId,
      proposal_intake_id: intakeId,
      proposal_run_id: proposalRunId,
      authorization_boot_id: this.#authorizationBootId,
      call_id: call.call_id,
      case_id: this.#caseId,
      session_id: call.session_id,
      conversation_version: conversationVersion,
      selection_id: call.selection_id,
      mandate_id: call.mandate_id,
      mandate_version: call.mandate_version,
      card_id: call.card_id,
      card_version: call.card_version,
      requested_id: call.requested_id,
      served_id: decision.served_id,
      system_use_decision: call.system_use_decision,
      policy_version: state.policy!.policy_version,
      policy_content_digest: state.policy!.policy_content_digest,
      projection_digest: call.projection_digest,
      projection_item_ids: call.projection_item_ids,
      output_digest: decision.output_digest,
      proposal_schema_digest: proposalSchemaDigest,
      revision_preparation_id: revisionPreparationId,
      issued_at: at,
      expires_at: expiresAt,
      state: 'issued',
      state_changed_at: at,
      proposal_id: null,
      refusal_reason: null,
    });
    return {
      op: { op: 'proposal_intake.issue', intake },
      reference: proposalIntakeReference.parse({
        proposal_intake_id: intakeId,
        proposal_run_id: intake.proposal_run_id,
        call_id: call.call_id,
        expires_at: expiresAt,
      }),
    };
  }

  #contentMatches(intake: ProposalIntakeRecord, content: string, state: WorldState): boolean {
    const call = state.modelCalls.get(intake.call_id);
    if (call === undefined || call.state !== 'terminal' || call.served_id === null) return false;
    return verifyDigest(
      intake.output_digest,
      digestModelOutput({
        turn_id: call.turn_id,
        selection_id: call.selection_id,
        mandate_id: call.mandate_id,
        mandate_version: call.mandate_version,
        card_id: call.card_id,
        card_version: call.card_version,
        requested_id: call.requested_id,
        served_id: call.served_id,
        projection_digest: call.projection_digest,
        content,
      }, this.#caseId),
    );
  }

  #isCurrent(state: WorldState, intake: ProposalIntakeRecord, at: string): ProposalGovernance {
    if (
      intake.authorization_boot_id !== this.#authorizationBootId ||
      at >= intake.expires_at ||
      (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== intake.conversation_version ||
      state.policy === undefined ||
      state.policy.policy_version !== intake.policy_version ||
      !verifyDigest(state.policy.policy_content_digest, intake.policy_content_digest) ||
      !this.#systemUse.isReferenceCurrent(state, intake.system_use_decision, at)
    ) throw new ProposalIntakeError('currentness', 'proposal intake is no longer current');
    this.#receipt(state, intake.session_id, at);
    const governance = this.#governance(state, at);
    const call = state.modelCalls.get(intake.call_id);
    const projection = this.#projection(state, governance);
    if (
      governance.selection.selection_id !== intake.selection_id ||
      governance.mandate.mandate_id !== intake.mandate_id ||
      governance.mandate.version !== intake.mandate_version ||
      governance.inspection.card.card_id !== intake.card_id ||
      governance.inspection.card.card_version !== intake.card_version ||
      call === undefined ||
      call.state !== 'terminal' ||
      call.outcome !== 'admitted' ||
      (intake.revision_preparation_id === null
        ? call.proposal_binding?.proposal_run_id !== intake.proposal_run_id || call.revision_binding !== null
        : call.revision_binding?.preparation_id !== intake.revision_preparation_id || call.proposal_binding !== null) ||
      call.served_id !== intake.served_id ||
      call.output_digest !== intake.output_digest ||
      projection.items.length === 0 ||
      canonicalize(projection.items.map((item) => item.id)) !== canonicalize(intake.projection_item_ids) ||
      !verifyDigest(digestFor('conversation-projection', projection), intake.projection_digest)
    ) throw new ProposalIntakeError('currentness', 'proposal intake binding is no longer current');
    if (intake.revision_preparation_id !== null) {
      const preparation = state.proposalRevisionPreparations.get(intake.revision_preparation_id);
      if (preparation === undefined || preparation.proposal_run_id !== intake.proposal_run_id) {
        throw new ProposalIntakeError('currentness', 'proposal revision intake lost its preparation');
      }
      this.#assertRevisionPreparationCurrent(state, at, preparation, intake.session_id, projection);
    }
    return governance;
  }

  async consume(
    intakeIdInput: string,
    content: string,
    actor: TransactionActor,
  ): Promise<ProposalIntakeConsumeResult | ProposalIntakeStatusProjection> {
    this.#requireOrchestrator(actor);
    const intakeId = id.parse(intakeIdInput);
    const proposalId = id.parse(this.#nextProposalId());
    const actionId = id.parse(this.#nextActionId());
    const completed = await this.#store.transactWithState<ProposalIntakeConsumeResult | ProposalIntakeStatusProjection>(
      'proposal_intake_consume',
      actor,
      (state, at) => {
        const intake = state.proposalIntakes.get(intakeId);
        if (intake === undefined) throw new ProposalIntakeError('not-found', 'proposal intake does not exist');
        if (intake.state === 'consumed') {
          if (!this.#contentMatches(intake, content, state) || intake.proposal_id === null) {
            throw new ProposalIntakeError('conflict', 'consumed proposal intake content changed');
          }
          return { ops: [], result: proposalIntakeConsumeResult.parse({
            kind: 'proposal_intake_consumption_result',
            proposal_run_id: intake.proposal_run_id,
            state: 'consumed',
            proposal_id: intake.proposal_id,
            recorded_at: intake.state_changed_at,
          }) };
        }
        if (intake.state !== 'issued') throw new ProposalIntakeError('conflict', 'proposal intake is terminal');
        if (!this.#contentMatches(intake, content, state)) {
          const op = { op: 'proposal_intake.refuse' as const, proposal_intake_id: intakeId, reason: 'invalid-content' as const, changed_at: at };
          return { ops: [op], result: this.#status({ ...intake, state: 'refused', state_changed_at: at, refusal_reason: 'invalid-content' }) };
        }
        let governance: ProposalGovernance;
        try {
          governance = this.#isCurrent(state, intake, at);
        } catch {
          const reason = (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== intake.conversation_version
            ? 'conversation-changed' as const
            : 'binding-invalidated' as const;
          const op = { op: 'proposal_intake.invalidate' as const, proposal_intake_id: intakeId, reason, changed_at: at };
          return { ops: [op], result: this.#status({ ...intake, state: 'invalidated', state_changed_at: at, refusal_reason: reason }) };
        }
        let draft: ProposalDraft;
        try {
          draft = parseProposalDraft(content);
        } catch {
          const op = { op: 'proposal_intake.refuse' as const, proposal_intake_id: intakeId, reason: 'invalid-content' as const, changed_at: at };
          return { ops: [op], result: this.#status({ ...intake, state: 'refused', state_changed_at: at, refusal_reason: 'invalid-content' }) };
        }
        const projection = this.#projection(state, governance);
        const byId = new Map(projection.items.map((item) => [item.id, item]));
        const material = draft.material_input_ids.map((itemId) => byId.get(itemId));
        const derived = draft.derived_claim_ids.map((itemId) => byId.get(itemId));
        if (
          material.some((item) => item === undefined || !['said', 'confirmed'].includes(item.store)) ||
          derived.some((item) => item === undefined || item.store !== 'inferred')
        ) {
          const op = { op: 'proposal_intake.refuse' as const, proposal_intake_id: intakeId, reason: 'invalid-evidence' as const, changed_at: at };
          return { ops: [op], result: this.#status({ ...intake, state: 'refused', state_changed_at: at, refusal_reason: 'invalid-evidence' }) };
        }
        const revisionPreparation =
          intake.revision_preparation_id === null
            ? undefined
            : state.proposalRevisionPreparations.get(intake.revision_preparation_id);
        const sourceProposal =
          revisionPreparation === undefined
            ? undefined
            : state.proposals.get(revisionPreparation.source_proposal_id);
        if (
          intake.revision_preparation_id !== null &&
          (revisionPreparation === undefined ||
            sourceProposal === undefined ||
            revisionPreparation.state !== 'consumed' ||
            revisionPreparation.proposal_run_id !== intake.proposal_run_id)
        ) {
          throw new ProposalIntakeError('currentness', 'proposal revision lineage is unavailable');
        }
        const proposal = freezeProposal({
          world_id: state.worldId,
          proposal_id: proposalId,
          revision: revisionPreparation?.expected_revision ?? 1,
          action_id: sourceProposal?.action_id ?? actionId,
          selection_id: intake.selection_id,
          created_at: at,
          declared_objective: draft.declared_objective,
          proposed_action: draft.proposed_action,
          target: draft.target,
          exact_parameters: draft.exact_parameters,
          material_inputs: material.map((item) => item!),
          derived_claims: derived.map((item) => item!),
          data_to_be_disclosed: draft.data_to_be_disclosed,
          cost_obligation: draft.cost_obligation,
          material_consequences: draft.material_consequences,
          reversibility_class: draft.reversibility_class,
          commercial_influence: draft.commercial_influence,
          acting_model: {
            requested_id: intake.requested_id,
            served_id: intake.served_id,
            card_id: intake.card_id,
            card_version: intake.card_version,
          },
          mandate_ref: { mandate_id: intake.mandate_id, version: intake.mandate_version },
        });
        const origin = proposalOriginRecord.parse({
          world_id: state.worldId,
          proposal_id: proposal.proposal_id,
          proposal_hash: proposal.proposal_hash,
          proposal_run_id: intake.proposal_run_id,
          call_id: intake.call_id,
          case_id: intake.case_id,
          session_id: intake.session_id,
          authorization_boot_id: intake.authorization_boot_id,
          conversation_version: intake.conversation_version,
          projection_item_ids: intake.projection_item_ids,
          projection_digest: intake.projection_digest,
          output_digest: intake.output_digest,
          selection_id: intake.selection_id,
          mandate_id: intake.mandate_id,
          mandate_version: intake.mandate_version,
          card_id: intake.card_id,
          card_version: intake.card_version,
          card_digest: governance.inspection.digest,
          verifying_key_id: governance.inspection.keyId,
          requested_id: intake.requested_id,
          served_id: intake.served_id,
          system_use_decision: intake.system_use_decision,
          policy_version: intake.policy_version,
          policy_content_digest: intake.policy_content_digest,
          evaluator_build_id: state.policy!.evaluator_build_id,
          service: governance.mandate.connected_service,
          action_class: governance.mandate.action_class,
          continuation:
            revisionPreparation === undefined
              ? null
              : {
                  preparation_id: revisionPreparation.preparation_id,
                  source_proposal_id: revisionPreparation.source_proposal_id,
                  source_ruling_id: revisionPreparation.source_ruling_id,
                  source_escalation_id: revisionPreparation.source_escalation_id,
                  response_record_entry_id: revisionPreparation.response_record_entry_id,
                },
          frozen_at: at,
        });
        return {
          ops: [
            { op: 'proposal.freeze', proposal },
            { op: 'proposal_origin.put', origin },
            { op: 'proposal_intake.consume', proposal_intake_id: intakeId, proposal_id: proposalId, changed_at: at },
          ],
          result: proposalIntakeConsumeResult.parse({
            kind: 'proposal_intake_consumption_result',
            proposal_run_id: intake.proposal_run_id,
            state: 'consumed',
            proposal_id: proposalId,
            recorded_at: at,
          }),
        };
      },
    );
    return completed.result;
  }

  #status(intakeInput: ProposalIntakeRecord): ProposalIntakeStatusProjection {
    const intake = proposalIntakeRecord.parse(intakeInput);
    return proposalIntakeStatusProjection.parse({
      kind: 'proposal_intake_status',
      proposal_intake_id: intake.proposal_intake_id,
      proposal_run_id: intake.proposal_run_id,
      call_id: intake.call_id,
      case_id: intake.case_id,
      state: intake.state,
      issued_at: intake.issued_at,
      expires_at: intake.expires_at,
      state_changed_at: intake.state_changed_at,
      proposal_id: intake.proposal_id,
      refusal_reason: intake.refusal_reason,
    });
  }

  status(intakeIdInput: string, actor: TransactionActor): ProposalIntakeStatusProjection {
    this.#requireOrchestrator(actor);
    const intake = this.#store.snapshot().proposalIntakes.get(id.parse(intakeIdInput));
    if (intake === undefined) throw new ProposalIntakeError('not-found', 'proposal intake does not exist');
    return this.#status(intake);
  }

  runStatus(caseIdInput: string, runIdInput: string, actor: TransactionActor): ProposalRunProcessProjection {
    this.#requireOrchestrator(actor);
    const caseId = id.parse(caseIdInput);
    const runId = id.parse(runIdInput);
    const state = this.#store.snapshot();
    const intakeId = state.proposalIntakeByRun.get(runId);
    const intake = intakeId === undefined ? undefined : state.proposalIntakes.get(intakeId);
    if (caseId !== this.#caseId || intake === undefined || intake.case_id !== caseId) {
      throw new ProposalIntakeError('not-found', 'proposal run does not exist for this case');
    }
    return proposalRunProcessProjection.parse({
      kind: 'proposal_run_status',
      proposal_run_id: intake.proposal_run_id,
      call_id: intake.call_id,
      case_id: intake.case_id,
      state: intake.state,
      issued_at: intake.issued_at,
      expires_at: intake.expires_at,
      state_changed_at: intake.state_changed_at,
      proposal_id: intake.proposal_id,
      refusal_reason: intake.refusal_reason,
    });
  }

  assertProposalCurrent(state: WorldState, at: string, proposalIdInput: string): void {
    const proposalId = id.parse(proposalIdInput);
    const proposal = state.proposals.get(proposalId);
    const origin = state.proposalOrigins.get(proposalId);
    if (
      proposal === undefined ||
      origin === undefined ||
      origin.case_id !== this.#caseId ||
      origin.authorization_boot_id !== this.#authorizationBootId ||
      proposal.proposal_hash !== origin.proposal_hash ||
      (state.conversationVersionByCase.get(this.#caseId) ?? 0) !== origin.conversation_version ||
      state.policy === undefined ||
      state.policy.policy_version !== origin.policy_version ||
      !verifyDigest(state.policy.policy_content_digest, origin.policy_content_digest) ||
      state.policy.evaluator_build_id !== origin.evaluator_build_id ||
      !this.#systemUse.isReferenceCurrent(state, origin.system_use_decision, at)
    ) {
      throw new ProposalIntakeError('currentness', 'native proposal origin is unavailable or stale');
    }
    this.#receipt(state, origin.session_id, at);
    const governance = this.#governance(state, at);
    const projection = this.#projection(state, governance);
    if (
      governance.selection.selection_id !== origin.selection_id ||
      governance.mandate.mandate_id !== origin.mandate_id ||
      governance.mandate.version !== origin.mandate_version ||
      governance.inspection.card.card_id !== origin.card_id ||
      governance.inspection.card.card_version !== origin.card_version ||
      !verifyDigest(governance.inspection.digest, origin.card_digest) ||
      governance.inspection.keyId !== origin.verifying_key_id ||
      canonicalize(projection.items.map((item) => item.id)) !== canonicalize(origin.projection_item_ids) ||
      !verifyDigest(digestFor('conversation-projection', projection), origin.projection_digest)
    ) {
      throw new ProposalIntakeError('currentness', 'native proposal governance or projection changed');
    }
    for (const item of [...proposal.material_inputs, ...proposal.derived_claims]) {
      const current = state.storeItems.get(item.id);
      if (current === undefined || current.case_id !== this.#caseId || canonicalize(current.item) !== canonicalize(item)) {
        throw new ProposalIntakeError('currentness', 'native proposal basis item changed');
      }
    }
    if (origin.continuation !== null) {
      const preparation = state.proposalRevisionPreparations.get(origin.continuation.preparation_id);
      const source = state.proposals.get(origin.continuation.source_proposal_id);
      const ruling = state.rulings.get(origin.continuation.source_ruling_id);
      const escalation = state.escalations.get(origin.continuation.source_escalation_id);
      const response = state.actionRecords.find(
        (entry) => entry.entry_id === origin.continuation?.response_record_entry_id,
      );
      if (
        preparation === undefined ||
        preparation.state !== 'consumed' ||
        preparation.proposal_run_id !== origin.proposal_run_id ||
        preparation.source_proposal_id !== source?.proposal_id ||
        preparation.expected_revision !== proposal.revision ||
        source?.action_id !== proposal.action_id ||
        ruling === undefined ||
        ruling.successor_ruling_id !== null ||
        escalation === undefined ||
        escalation.state !== 'disposed' ||
        escalation.successor_ruling_id !== null ||
        response?.human_intervention_event?.escalation_id !== escalation.escalation_id ||
        response.human_intervention_event.event !== 'human_intervention_event' ||
        response.human_intervention_event.payload.kind !== 'dialogue_response_recorded'
      ) {
        throw new ProposalIntakeError('currentness', 'proposal revision continuation is unavailable or already claimed');
      }
    }
  }

  async expire(actor: TransactionActor = { credential: 'proc:authz', claimed_role: null }): Promise<number> {
    const completed = await this.#store.transactWithState<number>('proposal_intake_expire', actor, (state, at) => {
      const intakeOps: WalOp[] = [...state.proposalIntakes.values()]
        .filter((intake) => intake.state === 'issued' && (intake.expires_at <= at || intake.authorization_boot_id !== this.#authorizationBootId))
        .map((intake) => intake.authorization_boot_id !== this.#authorizationBootId
          ? {
              op: 'proposal_intake.invalidate' as const,
              proposal_intake_id: intake.proposal_intake_id,
              reason: 'binding-invalidated' as const,
              changed_at: at,
            }
          : {
              op: 'proposal_intake.expire' as const,
              proposal_intake_id: intake.proposal_intake_id,
              authorization_boot_id: this.#authorizationBootId,
              changed_at: at,
            });
      const preparationOps: WalOp[] = [...state.proposalRevisionPreparations.values()]
        .filter((preparation) =>
          preparation.state === 'issued' &&
          (preparation.expires_at <= at || preparation.authorization_boot_id !== this.#authorizationBootId))
        .map((preparation) =>
          preparation.authorization_boot_id !== this.#authorizationBootId
            ? {
                op: 'proposal_revision_preparation.invalidate' as const,
                preparation_id: preparation.preparation_id,
                reason: 'authorization-restart' as const,
                changed_at: at,
              }
            : {
                op: 'proposal_revision_preparation.expire' as const,
                preparation_id: preparation.preparation_id,
                authorization_boot_id: this.#authorizationBootId,
                changed_at: at,
              });
      const priorBootProposalHashes = new Set(
        [...state.proposalOrigins.values()]
          .filter((origin) => origin.authorization_boot_id !== this.#authorizationBootId)
          .map((origin) => origin.proposal_hash),
      );
      const rulingOps: WalOp[] = [...state.rulings.values()]
        .filter((ruling) =>
          ruling.status === 'issued' &&
          priorBootProposalHashes.has(ruling.binding.frozen_proposal_hash) &&
          ['authorize', 'submit', 'verify'].includes(ruling.gate))
        .map((ruling) => ({
          op: 'ruling.invalidate' as const,
          ruling_id: ruling.ruling_id,
          reason: 'authorization-restart',
        }));
      const ops = [...intakeOps, ...preparationOps, ...rulingOps];
      return { ops, result: ops.length };
    });
    return completed.result;
  }
}
