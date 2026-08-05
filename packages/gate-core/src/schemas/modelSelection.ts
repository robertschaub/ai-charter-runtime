// SPDX-License-Identifier: AGPL-3.0-only
/** M5.7 authorization-owned model-selection lifecycle contracts. */
import { z } from 'zod';

import { cardSlug, credentialLabel, hexDigest, id, integer, modelId, timestamp, worldId } from './common.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

export const modelSelectionTarget = z
  .object({ card_id: cardSlug, card_version: integer.min(1), requested_id: modelId })
  .strict();
export type ModelSelectionTarget = z.infer<typeof modelSelectionTarget>;

export const boundModelSelectionTarget = modelSelectionTarget
  .extend({ card_digest: hexDigest, verifying_key_id: id })
  .strict();
export type BoundModelSelectionTarget = z.infer<typeof boundModelSelectionTarget>;

export const modelSelectionCheckRequest = z
  .object({
    expected_current_selection_id: id.nullable(),
    target: modelSelectionTarget,
  })
  .strict();
export type ModelSelectionCheckRequest = z.infer<typeof modelSelectionCheckRequest>;

export const modelSelectionCheckRecord = z
  .object({
    kind: z.literal('model_selection_check'),
    world_id: worldId,
    check_id: id,
    authorization_boot_id: id,
    case_id: id,
    authenticated_actor: credentialLabel,
    expected_current_selection_id: id.nullable(),
    mandate_id: id,
    mandate_version: integer.min(1),
    target: boundModelSelectionTarget,
    system_use_decision: systemUseDecisionReference,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    issued_at: timestamp,
    expires_at: timestamp,
    state: z.enum(['issued', 'consumed', 'expired']),
    consumed_at: timestamp.nullable(),
  })
  .strict()
  .superRefine((record, ctx) => {
    if (record.issued_at > record.expires_at) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'selection check expires before issue' });
    }
    if ((record.state === 'consumed') !== (record.consumed_at !== null)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['consumed_at'],
        message: 'only a consumed selection check carries consumed_at',
      });
    }
  });
export type ModelSelectionCheckRecord = z.infer<typeof modelSelectionCheckRecord>;

export const modelSelectionRequest = z
  .object({ check_id: id, expected_current_selection_id: id.nullable() })
  .strict();
export type ModelSelectionRequest = z.infer<typeof modelSelectionRequest>;

export const modelSelectionTransition = z
  .object({
    world_id: worldId,
    selection_id: id,
    case_id: id,
    kind: z.enum(['initial', 'switch']),
    predecessor_selection_id: id.nullable(),
    mandate_id: id,
    mandate_version: integer.min(1),
    target: boundModelSelectionTarget,
    system_use_decision: systemUseDecisionReference,
    check_id: id,
    selected_at: timestamp,
    authority_effect: z.literal('none'),
  })
  .strict()
  .superRefine((transition, ctx) => {
    if ((transition.kind === 'initial') !== (transition.predecessor_selection_id === null)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['predecessor_selection_id'],
        message: 'only an initial selection has no predecessor',
      });
    }
  });
export type ModelSelectionTransition = z.infer<typeof modelSelectionTransition>;

export const modelSelectionObservation = z
  .object({
    kind: z.literal('model_selection_observation'),
    world_id: worldId,
    observation_id: id,
    selection_id: id,
    call_id: id,
    served_id: modelId,
    model_resolution: z.enum(['exact', 'benign-resolution', 'mismatch']),
    terminal_outcome: z.enum(['admitted', 'withheld', 'failed']),
    observed_at: timestamp,
  })
  .strict();
export type ModelSelectionObservation = z.infer<typeof modelSelectionObservation>;

export const modelSelectionReadAccessEvidence = z
  .object({
    kind: z.literal('model_selection_read'),
    case_id: id,
    current_selection_id: id.nullable(),
    latest_observation_id: id.nullable(),
  })
  .strict();

export const modelSelectionResult = z
  .object({
    kind: z.literal('model_selection_result'),
    selection: modelSelectionTransition,
    invalidated_ruling_count: integer.min(0),
    terminalized_open_call_count: integer.min(0),
  })
  .strict();
export type ModelSelectionResult = z.infer<typeof modelSelectionResult>;

export const modelSelectionAccessEvidence = z.union([
  modelSelectionReadAccessEvidence,
  modelSelectionCheckRecord,
  modelSelectionResult,
]);
export type ModelSelectionAccessEvidence = z.infer<typeof modelSelectionAccessEvidence>;
