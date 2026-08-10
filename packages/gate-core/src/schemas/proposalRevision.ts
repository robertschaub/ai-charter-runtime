// SPDX-License-Identifier: AGPL-3.0-only
/** M5.12 authorization-owned proposal-revision preparation and redacted projections. */
import { z } from 'zod';

import {
  cardSlug,
  classToken,
  hexDigest,
  id,
  integer,
  jsonScalarOrList,
  modelId,
  nonNegativeMinorUnits,
  timestamp,
  worldId,
} from './common.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

const boundedText = z.string().min(1).max(4_096);
const boundedOptionalText = z.string().max(4_096);
const boundedTextArray = z.array(boundedText).max(64);

export const PROPOSAL_REVISION_PURPOSE = 'proposal-revision@1' as const;

/** The orchestrator carries only this opaque reference at model-call begin. */
export const proposalRevisionCallBinding = z.object({ preparation_id: id }).strict();
export type ProposalRevisionCallBinding = z.infer<typeof proposalRevisionCallBinding>;

export const proposalRevisionDisposition = z.enum(['confirm', 'correct', 'narrow']);
export const proposalRevisionPreparationState = z.enum(['issued', 'consumed', 'expired', 'invalidated']);
export const proposalRevisionInvalidationReason = z.enum([
  'authorization-restart',
  'session-ended',
  'conversation-changed',
  'selection-changed',
  'authority-changed',
  'successor-claimed',
]);

export const proposalRevisionPreparationRecord = z
  .object({
    world_id: worldId,
    preparation_id: id,
    proposal_run_id: id,
    authorization_boot_id: id,
    case_id: id,
    session_id: id,
    source_proposal_run_id: id,
    source_proposal_id: id,
    source_proposal_hash: hexDigest,
    action_id: id,
    source_revision: integer.min(1),
    expected_revision: integer.min(2),
    source_ruling_id: id,
    source_escalation_id: id,
    dialogue_item_ref: id,
    disposition: proposalRevisionDisposition,
    response_record_entry_id: id,
    conversation_version: integer.min(1),
    projection_digest: hexDigest,
    projection_item_ids: z.array(id).min(1).max(128),
    selection_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    card_id: cardSlug,
    card_version: integer.min(1),
    card_digest: hexDigest,
    verifying_key_id: id,
    requested_id: modelId,
    system_use_decision: systemUseDecisionReference,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    service: id,
    action_class: classToken,
    purpose: z.literal(PROPOSAL_REVISION_PURPOSE),
    proposal_schema_digest: hexDigest,
    issued_at: timestamp,
    expires_at: timestamp,
    state: proposalRevisionPreparationState,
    state_changed_at: timestamp,
    consumed_call_id: id.nullable(),
    invalidation_reason: proposalRevisionInvalidationReason.nullable(),
  })
  .strict()
  .superRefine((record, context) => {
    if (
      record.expected_revision <= record.source_revision ||
      record.issued_at > record.expires_at ||
      Date.parse(record.expires_at) - Date.parse(record.issued_at) > 2 * 60 * 1_000 ||
      record.state_changed_at < record.issued_at
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: 'proposal revision preparation bounds are inconsistent',
      });
    }
    if ((record.state === 'consumed') !== (record.consumed_call_id !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['consumed_call_id'],
        message: 'only a consumed revision preparation carries a model-call id',
      });
    }
    if ((record.state === 'invalidated') !== (record.invalidation_reason !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['invalidation_reason'],
        message: 'only an invalidated revision preparation carries an invalidation reason',
      });
    }
  });
export type ProposalRevisionPreparationRecord = z.infer<typeof proposalRevisionPreparationRecord>;

/** Semantic-only source proposal supplied to the provider; all lineage remains out of band. */
export const proposalRevisionSourceProjection = z
  .object({
    declared_objective: boundedText,
    proposed_action: boundedText,
    target: z.object({ recipient: boundedOptionalText, resource: boundedOptionalText }).strict(),
    exact_parameters: z.record(z.string().min(1).max(128), jsonScalarOrList),
    data_to_be_disclosed: boundedTextArray,
    cost_obligation: z.object({ amount_minor_units: nonNegativeMinorUnits, description: boundedOptionalText }).strict(),
    material_consequences: boundedTextArray,
    reversibility_class: classToken,
    commercial_influence: z.object({ applicable: z.boolean(), note: boundedOptionalText }).strict(),
    basis: z.array(z.object({ standing: z.enum(['said', 'confirmed', 'inferred-unconfirmed']), text: boundedText }).strict()).max(256),
  })
  .strict();
export type ProposalRevisionSourceProjection = z.infer<typeof proposalRevisionSourceProjection>;

export const proposalRevisionPreparationProjection = z
  .object({
    kind: z.literal('proposal_revision_preparation'),
    preparation_id: id,
    proposal_run_id: id,
    source_proposal_run_id: id,
    target: z.object({ card_id: cardSlug, card_version: integer.min(1), requested_id: modelId }).strict(),
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict();
export type ProposalRevisionPreparationProjection = z.infer<typeof proposalRevisionPreparationProjection>;

export const proposalRevisionContinuationState = z.enum([
  'unavailable',
  'response-required',
  'available',
  'prepared',
  'continued',
  'parked',
]);
export const proposalRevisionContinuationProjection = z
  .object({
    state: proposalRevisionContinuationState,
    source_proposal_run_id: id.nullable(),
  })
  .strict();
export type ProposalRevisionContinuationProjection = z.infer<typeof proposalRevisionContinuationProjection>;
