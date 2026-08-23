// SPDX-License-Identifier: AGPL-3.0-only
/** M6.2 native proposal-bound execution preparation and bounded projections. */
import { z } from 'zod';

import {
  cardSlug,
  classToken,
  hexDigest,
  id,
  integer,
  modelId,
  timestamp,
  worldId,
} from './common.js';
import { gate, rulingStatus, uxClass, verdict } from './ruling.js';
import { systemUseDecisionReference } from './systemUseDecision.js';
import { commitToken, effectIntent } from './token.js';

const executionCommitRulingProjection = z
  .object({
    gate: gate.refine((value) => value === 'commit'),
    ruling_id: id,
    verdict,
    ux_class: uxClass,
    reason: z.string().min(1),
    status: rulingStatus,
    validity_window: z.object({ not_before: timestamp, not_after: timestamp }).strict(),
  })
  .strict();

export const executionEffectIntentBasis = effectIntent.omit({ ruling_id: true });
export type ExecutionEffectIntentBasis = z.infer<typeof executionEffectIntentBasis>;

export const executionPreparationState = z.enum(['issued', 'consumed', 'expired', 'invalidated']);
export const executionPreparationEffectOutcome = z.enum([
  'success',
  'failed',
  'no-effect',
  'unknown-reconciliation-required',
]);

export const executionPreparationRecord = z
  .object({
    world_id: worldId,
    execution_preparation_id: id,
    authorization_boot_id: id,
    case_id: id,
    session_id: id,
    proposal_run_id: id,
    proposal_id: id,
    frozen_proposal_hash: hexDigest,
    action_id: id,
    revision: integer.min(1),
    conversation_version: integer.min(1),
    selection_id: id,
    requested_id: modelId,
    served_id: modelId,
    card_id: cardSlug,
    card_version: integer.min(1),
    card_digest: hexDigest,
    verifying_key_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    system_use_decision: systemUseDecisionReference,
    authorize_ruling_id: id,
    submit_ruling_id: id,
    verify_ruling_id: id,
    service: id,
    action_class: classToken,
    effect_intent_basis: executionEffectIntentBasis,
    effect_intent_basis_digest: hexDigest,
    issued_at: timestamp,
    expires_at: timestamp,
    state: executionPreparationState,
    state_changed_at: timestamp,
    commit_ruling_id: id.nullable(),
    escalation_id: id.nullable(),
    commitment_id: id.nullable(),
    effect_outcome: executionPreparationEffectOutcome.nullable(),
    effect_recorded_at: timestamp.nullable(),
    invalidation_reason: z.string().min(1).nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.issued_at > value.expires_at ||
      Date.parse(value.expires_at) - Date.parse(value.issued_at) > 2 * 60 * 1_000 ||
      value.state_changed_at < value.issued_at
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'invalid execution preparation lifetime' });
    }
    if ((value.state === 'invalidated') !== (value.invalidation_reason !== null)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['invalidation_reason'], message: 'only invalidated preparations carry a reason' });
    }
    if ((value.effect_outcome !== null) !== (value.effect_recorded_at !== null)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['effect_outcome'], message: 'effect outcome and time must appear together' });
    }
    if (value.commitment_id === null && value.effect_outcome !== null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['effect_outcome'], message: 'only a committed preparation can carry an effect outcome' });
    }
    if (value.state !== 'consumed' && [value.commit_ruling_id, value.escalation_id, value.commitment_id, value.effect_outcome, value.effect_recorded_at].some((field) => field !== null)) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['state'], message: 'only consumed preparations carry terminal commit correlation' });
    }
  });
export type ExecutionPreparationRecord = z.infer<typeof executionPreparationRecord>;

export const executionPreparationProjection = z
  .object({
    kind: z.literal('execution_preparation'),
    execution_preparation_id: id,
    proposal_run_id: id,
    state: z.literal('issued'),
    issued_at: timestamp,
    expires_at: timestamp,
  })
  .strict();
export type ExecutionPreparationProjection = z.infer<typeof executionPreparationProjection>;

export const executionProcessState = z.enum([
  'unavailable',
  'available',
  'prepared',
  'commit-denied',
  'commit-escalated',
  'committed',
  'effect-recorded',
  'no-effect',
  'indeterminate',
]);

export const executionProcessProjection = z
  .object({
    state: executionProcessState,
    execution_preparation_id: id.nullable(),
    expires_at: timestamp.nullable(),
    commit_ruling: executionCommitRulingProjection.nullable(),
    escalation_id: id.nullable(),
    commitment_id: id.nullable(),
    effect_id: id.nullable(),
    idempotency_key: hexDigest.nullable(),
    effect_outcome: executionPreparationEffectOutcome.nullable(),
    recorded_at: timestamp.nullable(),
  })
  .strict();
export type ExecutionProcessProjection = z.infer<typeof executionProcessProjection>;

export const nativeCommitVerifyRequest = z
  .object({ services_host_boot_id: id, services_ledger_id: id })
  .strict();

export const nativeCommitVerifyResult = z.discriminatedUnion('state', [
  z.object({
    execution_preparation_id: id,
    state: z.literal('commit-denied'),
    ruling: executionCommitRulingProjection,
    escalation_id: z.null(),
  }).strict(),
  z.object({
    execution_preparation_id: id,
    state: z.literal('commit-escalated'),
    ruling: executionCommitRulingProjection,
    escalation_id: id,
  }).strict(),
  z.object({
    execution_preparation_id: id,
    state: z.literal('committed'),
    ruling: executionCommitRulingProjection,
    escalation_id: z.null(),
    intent: effectIntent,
    token: commitToken,
    commitment_id: id,
    record_entry_id: id,
  }).strict(),
  z.object({
    execution_preparation_id: id,
    state: z.literal('already-consumed'),
    commitment_id: id,
    idempotency_key: hexDigest,
    effect_outcome: executionPreparationEffectOutcome.nullable(),
    recorded_at: timestamp.nullable(),
  }).strict(),
]);
export type NativeCommitVerifyResult = z.infer<typeof nativeCommitVerifyResult>;

export const nativeServicesExecutionResult = z
  .object({
    execution_preparation_id: id,
    state: z.enum(['preparation-unavailable', 'commit-denied', 'commit-escalated', 'effect-recorded', 'no-effect', 'indeterminate']),
    effect_outcome: executionPreparationEffectOutcome.nullable(),
    recorded_at: timestamp.nullable(),
  })
  .strict();
export type NativeServicesExecutionResult = z.infer<typeof nativeServicesExecutionResult>;

export const browserExecutionProjection = z
  .object({
    state: executionProcessState,
    execution_preparation_id: id.optional(),
    expires_at: timestamp.optional(),
    commit_ruling: executionCommitRulingProjection.optional(),
    escalation_id: id.optional(),
    effect_outcome: executionPreparationEffectOutcome.nullable(),
    recorded_at: timestamp.nullable(),
  })
  .strict();
export type BrowserExecutionProjection = z.infer<typeof browserExecutionProjection>;

export const browserExecutionPreparation = z
  .object({
    execution_preparation_id: id,
    proposal_run_id: id,
    state: z.literal('prepared'),
    expires_at: timestamp,
  })
  .strict();

export const browserExecutionRequest = z.object({ execution_preparation_id: id }).strict();
