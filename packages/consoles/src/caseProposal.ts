// SPDX-License-Identifier: MIT
/** M5.11 dynamic-session proposal preparation and exact-key browser projection. */
import { randomBytes } from 'node:crypto';

import {
  id,
  integer,
  modelSelectionTarget,
  proposalPrecommitGateProjection,
  proposalPrecommitProjection,
  proposalRunProcessProjection,
  proposalRevisionContinuationProjection,
  timestamp,
  type ConversationProcessProjection,
  type CurrentModelSelectionProjection,
  type ModelSelectionTarget,
  type ProposalPrecommitProjection,
  type ProposalRunProcessProjection,
  type ProposalRevisionPreparationProjection,
} from 'gate-core';
import { z } from 'zod';

import type { CaseSessionRecord } from './caseSessionStore.js';

const MAX_TTL_MS = 2 * 60 * 1_000;
const MAX_RECORDS = 128;

export const browserProposalPreparationRequest = z.object({}).strict();
export const browserProposalUseRequest = z.object({ preparation_id: id }).strict();
export const browserProposalPreparation = z
  .object({
    preparation_id: id,
    proposal_run_id: id,
    target: modelSelectionTarget,
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict();
export type BrowserProposalPreparation = z.infer<typeof browserProposalPreparation>;

const browserProposal = proposalPrecommitProjection.shape.proposal;
const browserGate = proposalPrecommitGateProjection;
export const browserProposalRunStatus = z
  .object({
    proposal_run_id: id,
    state: z.enum(['prepared', 'running', 'frozen', 'denied', 'escalated', 'verified', 'failed']),
    proposal: browserProposal.optional(),
    gates: z.array(browserGate).max(3),
    escalation_id: id.optional(),
    continuation: proposalRevisionContinuationProjection,
  })
  .strict()
  .superRefine((value, context) => {
    if (['frozen', 'denied', 'escalated', 'verified'].includes(value.state) && value.proposal === undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['proposal'], message: 'durable proposal states require the redacted proposal' });
    }
    if (['prepared', 'running'].includes(value.state) && value.proposal !== undefined) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['proposal'], message: 'pre-durable proposal states cannot expose a proposal' });
    }
    if ((value.state === 'escalated') !== (value.escalation_id !== undefined)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['escalation_id'], message: 'only an escalated run exposes an escalation id' });
    }
  });
export type BrowserProposalRunStatus = z.infer<typeof browserProposalRunStatus>;

interface ProposalRecord {
  readonly kind: 'initial' | 'revision';
  readonly preparationId: string;
  readonly proposalRunId: string;
  readonly turnId: string;
  readonly sessionId: string;
  readonly sessionExpiresAt: string;
  readonly worldId: string;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly conversationVersion: number;
  readonly revisionPreparationId: string | null;
  readonly sourceProposalRunId: string | null;
  readonly selectionId: string;
  readonly target: ModelSelectionTarget;
  readonly issuedAt: string;
  readonly expiresAt: string;
  state: 'prepared' | 'running' | 'failed';
}

export type BegunProposalRun = {
  readonly kind: 'initial';
  readonly proposalRunId: string;
  readonly turnId: string;
  readonly conversationVersion: number;
  readonly selectionId: string;
  readonly target: ModelSelectionTarget;
} | {
  readonly kind: 'revision';
  readonly proposalRunId: string;
  readonly sourceProposalRunId: string;
  readonly turnId: string;
  readonly preparationId: string;
  readonly selectionId: string;
  readonly target: ModelSelectionTarget;
};

export interface CaseProposalStoreOptions {
  readonly ttlMs?: number;
  readonly maxRecords?: number;
  readonly now?: () => string;
  readonly nextPreparationId?: () => string;
  readonly nextRunId?: () => string;
  readonly nextTurnId?: () => string;
}

function sameSession(record: ProposalRecord, session: CaseSessionRecord): boolean {
  return record.sessionId === session.session_id &&
    record.worldId === session.world_id &&
    record.caseId === session.case_id &&
    record.authorizationBootId === session.authorization_boot_id;
}

export function toBrowserProposalRunStatus(
  input: ProposalRunProcessProjection | ProposalPrecommitProjection,
): BrowserProposalRunStatus {
  const precommit = proposalPrecommitProjection.safeParse(input);
  if (precommit.success) {
    const value = precommit.data;
    return browserProposalRunStatus.parse({
      proposal_run_id: value.proposal_run_id,
      state: value.state,
      proposal: {
        proposal_id: value.proposal.proposal_id,
        action_id: value.proposal.action_id,
        revision: value.proposal.revision,
        declared_objective: value.proposal.declared_objective,
        proposed_action: value.proposal.proposed_action,
        target: { recipient: value.proposal.target.recipient, resource: value.proposal.target.resource },
        exact_parameters: Object.fromEntries(
          Object.entries(value.proposal.exact_parameters).map(([key, parameter]) => [
            key,
            Array.isArray(parameter) ? [...parameter] : parameter,
          ]),
        ),
        data_to_be_disclosed: [...value.proposal.data_to_be_disclosed],
        cost_obligation: {
          amount_minor_units: value.proposal.cost_obligation.amount_minor_units,
          description: value.proposal.cost_obligation.description,
        },
        material_consequences: [...value.proposal.material_consequences],
        reversibility_class: value.proposal.reversibility_class,
        commercial_influence: {
          applicable: value.proposal.commercial_influence.applicable,
          note: value.proposal.commercial_influence.note,
        },
        requested_id: value.proposal.requested_id,
        served_id: value.proposal.served_id,
        basis: value.proposal.basis.map((basis) => ({ standing: basis.standing, text: basis.text })),
      },
      gates: value.gates.map((gateValue) => ({
        gate: gateValue.gate,
        ruling_id: gateValue.ruling_id,
        verdict: gateValue.verdict,
        ux_class: gateValue.ux_class,
        reason: gateValue.reason,
        status: gateValue.status,
        validity_window: {
          not_before: gateValue.validity_window.not_before,
          not_after: gateValue.validity_window.not_after,
        },
      })),
      ...(value.escalation_id === null ? {} : { escalation_id: value.escalation_id }),
      continuation: value.continuation,
    });
  }
  const value = proposalRunProcessProjection.parse(input);
  return browserProposalRunStatus.parse({
    proposal_run_id: value.proposal_run_id,
    state: value.state === 'issued' ? 'running' : value.state === 'consumed' ? 'frozen' : 'failed',
    gates: [],
    continuation: { state: 'unavailable', source_proposal_run_id: null },
  });
}

export class CaseProposalStore {
  readonly #recordsByRun = new Map<string, ProposalRecord>();
  readonly #runByPreparation = new Map<string, string>();
  readonly #currentPreparationBySession = new Map<string, string>();
  readonly #ttlMs: number;
  readonly #maxRecords: number;
  readonly #now: () => string;
  readonly #nextPreparationId: () => string;
  readonly #nextRunId: () => string;
  readonly #nextTurnId: () => string;

  constructor(options: CaseProposalStoreOptions = {}) {
    this.#ttlMs = integer.min(1).max(MAX_TTL_MS).parse(options.ttlMs ?? MAX_TTL_MS);
    this.#maxRecords = integer.min(1).max(MAX_RECORDS).parse(options.maxRecords ?? MAX_RECORDS);
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#nextPreparationId = options.nextPreparationId ?? (() => `pprep_${randomBytes(16).toString('hex')}`);
    this.#nextRunId = options.nextRunId ?? (() => `prun_${randomBytes(16).toString('hex')}`);
    this.#nextTurnId = options.nextTurnId ?? (() => `turn_${randomBytes(16).toString('hex')}`);
  }

  #deletePrepared(record: ProposalRecord): void {
    this.#recordsByRun.delete(record.proposalRunId);
    this.#runByPreparation.delete(record.preparationId);
    if (this.#currentPreparationBySession.get(record.sessionId) === record.preparationId) {
      this.#currentPreparationBySession.delete(record.sessionId);
    }
  }

  create(
    session: CaseSessionRecord,
    current: CurrentModelSelectionProjection,
    conversation: ConversationProcessProjection,
  ): BrowserProposalPreparation {
    const at = timestamp.parse(this.#now());
    if (
      session.state !== 'active' ||
      session.expires_at <= at ||
      current.state !== 'selected' ||
      current.authorization_boot_id !== session.authorization_boot_id ||
      current.case_id !== session.case_id ||
      current.selection.world_id !== session.world_id ||
      current.selection.case_id !== session.case_id ||
      conversation.case_id !== session.case_id ||
      conversation.conversation_version < 1 ||
      conversation.events.length === 0
    ) throw new Error('proposal-preparation-binding-invalid');
    const priorPreparation = this.#currentPreparationBySession.get(session.session_id);
    const priorRun = priorPreparation === undefined ? undefined : this.#runByPreparation.get(priorPreparation);
    const prior = priorRun === undefined ? undefined : this.#recordsByRun.get(priorRun);
    if (prior?.state === 'prepared') this.#deletePrepared(prior);
    if (this.#recordsByRun.size >= this.#maxRecords) throw new Error('proposal-preparation-capacity');
    const preparationId = id.parse(this.#nextPreparationId());
    const proposalRunId = id.parse(this.#nextRunId());
    const turnId = id.parse(this.#nextTurnId());
    if (this.#runByPreparation.has(preparationId) || this.#recordsByRun.has(proposalRunId)) {
      throw new Error('proposal preparation identifier source repeated a value');
    }
    const expiresAt = timestamp.parse(new Date(Math.min(Date.parse(at) + this.#ttlMs, Date.parse(session.expires_at))).toISOString());
    const target = modelSelectionTarget.parse({
      card_id: current.selection.target.card_id,
      card_version: current.selection.target.card_version,
      requested_id: current.selection.target.requested_id,
    });
    const record: ProposalRecord = {
      kind: 'initial',
      preparationId,
      proposalRunId,
      turnId,
      sessionId: session.session_id,
      sessionExpiresAt: session.expires_at,
      worldId: session.world_id,
      caseId: session.case_id,
      authorizationBootId: session.authorization_boot_id,
      conversationVersion: conversation.conversation_version,
      revisionPreparationId: null,
      sourceProposalRunId: null,
      selectionId: current.selection.selection_id,
      target,
      issuedAt: at,
      expiresAt,
      state: 'prepared',
    };
    this.#recordsByRun.set(proposalRunId, record);
    this.#runByPreparation.set(preparationId, proposalRunId);
    this.#currentPreparationBySession.set(session.session_id, preparationId);
    return browserProposalPreparation.parse({ preparation_id: preparationId, proposal_run_id: proposalRunId, target, issued_at: at, expires_at: expiresAt });
  }

  registerRevision(
    session: CaseSessionRecord,
    current: CurrentModelSelectionProjection,
    preparationInput: ProposalRevisionPreparationProjection,
  ): BrowserProposalPreparation {
    const preparation = preparationInput;
    const at = timestamp.parse(this.#now());
    if (
      session.state !== 'active' ||
      session.expires_at <= at ||
      current.state !== 'selected' ||
      current.authorization_boot_id !== session.authorization_boot_id ||
      current.case_id !== session.case_id ||
      current.selection.world_id !== session.world_id ||
      current.selection.case_id !== session.case_id ||
      current.selection.target.card_id !== preparation.target.card_id ||
      current.selection.target.card_version !== preparation.target.card_version ||
      current.selection.target.requested_id !== preparation.target.requested_id ||
      preparation.expires_at <= at
    ) throw new Error('proposal-revision-preparation-binding-invalid');
    const existingRunId = this.#runByPreparation.get(preparation.preparation_id);
    const existing = existingRunId === undefined ? undefined : this.#recordsByRun.get(existingRunId);
    if (
      existing !== undefined &&
      existing.kind === 'revision' &&
      existing.proposalRunId === preparation.proposal_run_id &&
      sameSession(existing, session)
    ) {
      return browserProposalPreparation.parse({
        preparation_id: existing.preparationId,
        proposal_run_id: existing.proposalRunId,
        target: existing.target,
        issued_at: existing.issuedAt,
        expires_at: existing.expiresAt,
      });
    }
    if (existingRunId !== undefined || this.#recordsByRun.has(preparation.proposal_run_id)) {
      throw new Error('proposal revision preparation already registered');
    }
    const priorPreparation = this.#currentPreparationBySession.get(session.session_id);
    const priorRun = priorPreparation === undefined ? undefined : this.#runByPreparation.get(priorPreparation);
    const prior = priorRun === undefined ? undefined : this.#recordsByRun.get(priorRun);
    if (prior?.state === 'prepared') this.#deletePrepared(prior);
    if (this.#recordsByRun.size >= this.#maxRecords) throw new Error('proposal-preparation-capacity');
    const turnId = id.parse(this.#nextTurnId());
    const target = modelSelectionTarget.parse(preparation.target);
    const record: ProposalRecord = {
      kind: 'revision',
      preparationId: preparation.preparation_id,
      proposalRunId: preparation.proposal_run_id,
      turnId,
      sessionId: session.session_id,
      sessionExpiresAt: session.expires_at,
      worldId: session.world_id,
      caseId: session.case_id,
      authorizationBootId: session.authorization_boot_id,
      conversationVersion: 0,
      revisionPreparationId: preparation.preparation_id,
      sourceProposalRunId: preparation.source_proposal_run_id,
      selectionId: current.selection.selection_id,
      target,
      issuedAt: preparation.issued_at,
      expiresAt: preparation.expires_at,
      state: 'prepared',
    };
    this.#recordsByRun.set(record.proposalRunId, record);
    this.#runByPreparation.set(record.preparationId, record.proposalRunId);
    this.#currentPreparationBySession.set(record.sessionId, record.preparationId);
    return browserProposalPreparation.parse({
      preparation_id: record.preparationId,
      proposal_run_id: record.proposalRunId,
      target,
      issued_at: record.issuedAt,
      expires_at: record.expiresAt,
    });
  }

  beginUse(preparationIdInput: string, session: CaseSessionRecord): BegunProposalRun | null {
    const preparationId = id.parse(preparationIdInput);
    const runId = this.#runByPreparation.get(preparationId);
    const record = runId === undefined ? undefined : this.#recordsByRun.get(runId);
    const at = timestamp.parse(this.#now());
    if (record === undefined || record.state !== 'prepared' || !sameSession(record, session) || record.expiresAt <= at || record.sessionExpiresAt <= at) return null;
    record.state = 'running';
    this.#runByPreparation.delete(preparationId);
    this.#currentPreparationBySession.delete(record.sessionId);
    return record.kind === 'initial'
      ? {
          kind: 'initial',
          proposalRunId: record.proposalRunId,
          turnId: record.turnId,
          conversationVersion: record.conversationVersion,
          selectionId: record.selectionId,
          target: record.target,
        }
      : {
          kind: 'revision',
          proposalRunId: record.proposalRunId,
          sourceProposalRunId: record.sourceProposalRunId!,
          turnId: record.turnId,
          preparationId: record.revisionPreparationId!,
          selectionId: record.selectionId,
          target: record.target,
        };
  }

  fail(runIdInput: string): BrowserProposalRunStatus {
    const record = this.#recordsByRun.get(id.parse(runIdInput));
    if (record === undefined) throw new Error('proposal-run-missing');
    record.state = 'failed';
    return browserProposalRunStatus.parse({
      proposal_run_id: record.proposalRunId,
      state: 'failed',
      gates: [],
      continuation: {
        state: 'unavailable',
        source_proposal_run_id: record.sourceProposalRunId,
      },
    });
  }

  localStatus(runIdInput: string, session: CaseSessionRecord): BrowserProposalRunStatus | null {
    const record = this.#recordsByRun.get(id.parse(runIdInput));
    if (record === undefined || !sameSession(record, session)) return null;
    return browserProposalRunStatus.parse({
      proposal_run_id: record.proposalRunId,
      state: record.state,
      gates: [],
      continuation: {
        state: record.kind === 'revision' && record.state !== 'failed' ? 'prepared' : 'unavailable',
        source_proposal_run_id: record.sourceProposalRunId,
      },
    });
  }

  discardResolved(runIdInput: string): void {
    const record = this.#recordsByRun.get(id.parse(runIdInput));
    if (record !== undefined && record.state !== 'prepared') this.#deletePrepared(record);
  }

  burnForSession(sessionIdInput: string): void {
    const sessionId = id.parse(sessionIdInput);
    for (const record of [...this.#recordsByRun.values()]) if (record.sessionId === sessionId && record.state === 'prepared') this.#deletePrepared(record);
  }

  burnForCase(worldIdInput: string, caseIdInput: string): void {
    for (const record of [...this.#recordsByRun.values()]) if (record.worldId === worldIdInput && record.caseId === caseIdInput && record.state === 'prepared') this.#deletePrepared(record);
  }

  burnStaleForCase(worldIdInput: string, caseIdInput: string, currentSelectionId: string | null): void {
    for (const record of [...this.#recordsByRun.values()]) {
      if (
        record.worldId === worldIdInput &&
        record.caseId === caseIdInput &&
        record.selectionId !== currentSelectionId &&
        record.state === 'prepared'
      ) this.#deletePrepared(record);
    }
  }

  expire(): void {
    const at = timestamp.parse(this.#now());
    for (const record of [...this.#recordsByRun.values()]) if (record.state === 'prepared' && (record.expiresAt <= at || record.sessionExpiresAt <= at)) this.#deletePrepared(record);
  }

  clear(): void {
    this.#recordsByRun.clear();
    this.#runByPreparation.clear();
    this.#currentPreparationBySession.clear();
  }
}
