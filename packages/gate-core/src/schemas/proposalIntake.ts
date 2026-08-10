// SPDX-License-Identifier: AGPL-3.0-only
/** M5.11 purpose-bound proposal draft, durable intake, and origin evidence. */
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
import { proposalRevisionCallBinding } from './proposalRevision.js';

const boundedText = z.string().min(1).max(4_096);
const boundedOptionalText = z.string().max(4_096);
const boundedTextArray = z.array(boundedText).max(64);
const boundedJsonScalarOrList = jsonScalarOrList.refine(
  (value) => !Array.isArray(value) || value.length <= 64,
  { message: 'proposal draft parameter arrays exceed the fixed capacity' },
);
const uniqueIds = z.array(id).max(128).refine((values) => new Set(values).size === values.length, {
  message: 'proposal draft item ids must be unique',
});
const uniqueNonEmptyIds = z.array(id).min(1).max(128).refine((values) => new Set(values).size === values.length, {
  message: 'proposal projection item ids must be unique',
});
const forbiddenParameterKey = /(?:^|_)(?:world|case|proposal|action|revision|time|selection|model|card|mandate|service|item|store|tags?|provenance|policy|system_use|hash|gate|ruling|nonce|reservation|token|disposition|authority|prompt|schema|output|call|intake|release|session|boot|digest)(?:_|$)/u;

export const PROPOSAL_SCHEMA_ID = 'proposal-draft@1' as const;

export const proposalCallBinding = z
  .object({
    proposal_run_id: id,
    conversation_version: integer.min(1),
    proposal_schema_digest: hexDigest,
  })
  .strict();
export type ProposalCallBinding = z.infer<typeof proposalCallBinding>;

export const proposalDraft = z
  .object({
    declared_objective: boundedText,
    proposed_action: boundedText,
    target: z.object({ recipient: boundedOptionalText, resource: boundedOptionalText }).strict(),
    exact_parameters: z.record(z.string().min(1).max(128), boundedJsonScalarOrList),
    material_input_ids: uniqueIds,
    derived_claim_ids: uniqueIds,
    data_to_be_disclosed: boundedTextArray,
    cost_obligation: z
      .object({ amount_minor_units: nonNegativeMinorUnits, description: boundedOptionalText })
      .strict(),
    material_consequences: boundedTextArray,
    reversibility_class: classToken,
    commercial_influence: z
      .object({ applicable: z.boolean(), note: boundedOptionalText })
      .strict(),
  })
  .strict()
  .superRefine((value, context) => {
    if (Object.keys(value.exact_parameters).length > 64) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['exact_parameters'],
        message: 'proposal draft exact parameters exceed the fixed capacity',
      });
    }
    if (Object.keys(value.exact_parameters).some((key) => forbiddenParameterKey.test(key))) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['exact_parameters'],
        message: 'proposal draft exact parameters contain a reserved authority or transport field',
      });
    }
    const material = new Set(value.material_input_ids);
    if (value.derived_claim_ids.some((candidate) => material.has(candidate))) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['derived_claim_ids'],
        message: 'material and derived proposal item ids must be disjoint',
      });
    }
  });
export type ProposalDraft = z.infer<typeof proposalDraft>;

export const proposalIntakeState = z.enum(['issued', 'consumed', 'refused', 'invalidated', 'expired']);
export const proposalIntakeRefusalReason = z.enum([
  'invalid-content',
  'invalid-evidence',
  'binding-invalidated',
  'conversation-changed',
]);

export const proposalIntakeRecord = z
  .object({
    world_id: worldId,
    proposal_intake_id: id,
    proposal_run_id: id,
    authorization_boot_id: id,
    call_id: id,
    case_id: id,
    session_id: id,
    conversation_version: integer.min(1),
    selection_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    card_id: cardSlug,
    card_version: integer.min(1),
    requested_id: modelId,
    served_id: modelId,
    system_use_decision: systemUseDecisionReference,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    projection_digest: hexDigest,
    projection_item_ids: uniqueNonEmptyIds,
    output_digest: hexDigest,
    proposal_schema_digest: hexDigest,
    revision_preparation_id: id.nullable().default(null),
    issued_at: timestamp,
    expires_at: timestamp,
    state: proposalIntakeState,
    state_changed_at: timestamp,
    proposal_id: id.nullable(),
    refusal_reason: proposalIntakeRefusalReason.nullable(),
  })
  .strict()
  .superRefine((record, context) => {
    if (
      record.issued_at > record.expires_at ||
      Date.parse(record.expires_at) - Date.parse(record.issued_at) > 2 * 60 * 1_000 ||
      record.state_changed_at < record.issued_at
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: 'proposal intake lifetime or state timestamp is invalid',
      });
    }
    if ((record.state === 'consumed') !== (record.proposal_id !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['proposal_id'],
        message: 'only a consumed proposal intake carries a proposal id',
      });
    }
    if ((record.state === 'refused' || record.state === 'invalidated') !== (record.refusal_reason !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['refusal_reason'],
        message: 'only refused or invalidated proposal intake carries a refusal reason',
      });
    }
  });
export type ProposalIntakeRecord = z.infer<typeof proposalIntakeRecord>;

export const proposalOriginRecord = z
  .object({
    world_id: worldId,
    proposal_id: id,
    proposal_hash: hexDigest,
    proposal_run_id: id,
    call_id: id,
    case_id: id,
    session_id: id,
    authorization_boot_id: id,
    conversation_version: integer.min(1),
    projection_item_ids: uniqueNonEmptyIds,
    projection_digest: hexDigest,
    output_digest: hexDigest,
    selection_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    card_id: cardSlug,
    card_version: integer.min(1),
    card_digest: hexDigest,
    verifying_key_id: id,
    requested_id: modelId,
    served_id: modelId,
    system_use_decision: systemUseDecisionReference,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    service: id,
    action_class: classToken,
    continuation: z
      .object({
        preparation_id: id,
        source_proposal_id: id,
        source_ruling_id: id,
        source_escalation_id: id,
        response_record_entry_id: id,
      })
      .strict()
      .nullable()
      .default(null),
    frozen_at: timestamp,
  })
  .strict();
export type ProposalOriginRecord = z.infer<typeof proposalOriginRecord>;

/** Intake linkage is null for an initial proposal and opaque for a revision call. */
export const proposalIntakeRevisionBinding = proposalRevisionCallBinding.nullable().default(null);

export const proposalIntakeReference = z
  .object({
    proposal_intake_id: id,
    proposal_run_id: id,
    call_id: id,
    expires_at: timestamp,
  })
  .strict();
export type ProposalIntakeReference = z.infer<typeof proposalIntakeReference>;

export const proposalIntakeConsumeResult = z
  .object({
    kind: z.literal('proposal_intake_consumption_result'),
    proposal_run_id: id,
    state: z.literal('consumed'),
    proposal_id: id,
    recorded_at: timestamp,
  })
  .strict();
export type ProposalIntakeConsumeResult = z.infer<typeof proposalIntakeConsumeResult>;

export const proposalIntakeStatusProjection = z
  .object({
    kind: z.literal('proposal_intake_status'),
    proposal_intake_id: id,
    proposal_run_id: id,
    call_id: id,
    case_id: id,
    state: proposalIntakeState,
    issued_at: timestamp,
    expires_at: timestamp,
    state_changed_at: timestamp,
    proposal_id: id.nullable(),
    refusal_reason: proposalIntakeRefusalReason.nullable(),
  })
  .strict();
export type ProposalIntakeStatusProjection = z.infer<typeof proposalIntakeStatusProjection>;

export const proposalRunProcessProjection = z
  .object({
    kind: z.literal('proposal_run_status'),
    proposal_run_id: id,
    call_id: id,
    case_id: id,
    state: proposalIntakeState,
    issued_at: timestamp,
    expires_at: timestamp,
    state_changed_at: timestamp,
    proposal_id: id.nullable(),
    refusal_reason: proposalIntakeRefusalReason.nullable(),
  })
  .strict();
export type ProposalRunProcessProjection = z.infer<typeof proposalRunProcessProjection>;

export const proposalIntakeAccessEvidence = z.union([
  proposalIntakeStatusProjection,
  proposalRunProcessProjection,
  proposalIntakeConsumeResult,
]);
export type ProposalIntakeAccessEvidence = z.infer<typeof proposalIntakeAccessEvidence>;
