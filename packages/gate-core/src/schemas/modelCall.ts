// SPDX-License-Identifier: AGPL-3.0-only
/** M5.5 durable, metadata-only model-call lifecycle contracts. */
import { z } from 'zod';

import { cardSlug, hexDigest, id, integer, modelId, timestamp, worldId } from './common.js';
import { modelCallIngressBinding, outputReleaseReference } from './conversationTransport.js';
import { modelOutputAdmission, modelOutputAdmissionRequest } from './output.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

export const MODEL_CALL_REPORTABLE_FAILURE_REASONS = [
  'provider-timeout',
  'provider-unavailable',
  'malformed-response',
  'tool-calls-refused',
  'authorization-invalidated',
  'system-use-invalidated',
] as const;
export const modelCallReportableFailureReason = z.enum(MODEL_CALL_REPORTABLE_FAILURE_REASONS);
export const MODEL_CALL_FAILURE_REASONS = [...MODEL_CALL_REPORTABLE_FAILURE_REASONS, 'selection-invalidated'] as const;
export const modelCallFailureReason = z.enum(MODEL_CALL_FAILURE_REASONS);
export type ModelCallFailureReason = z.infer<typeof modelCallFailureReason>;
export type ModelCallReportableFailureReason = z.infer<typeof modelCallReportableFailureReason>;

export const modelCallBeginRequest = z
  .object({
    turn_id: id,
    selection_id: id,
    ingress_binding: modelCallIngressBinding.nullable().default(null),
  })
  .strict();
export type ModelCallBeginRequest = z.infer<typeof modelCallBeginRequest>;

const modelCallBinding = z.object({
  kind: z.literal('model_call_lifecycle'),
  world_id: worldId,
  call_id: id,
  authorization_boot_id: id,
  case_id: id,
  turn_id: id,
  selection_id: id,
  mandate_id: id,
  mandate_version: integer.min(1),
  card_id: cardSlug,
  card_version: integer.min(1),
  requested_id: modelId,
  projection_digest: hexDigest,
  projection_item_count: integer.min(0),
  projection_item_ids: z.array(id).default([]),
  ingress_binding: modelCallIngressBinding.nullable().default(null),
  session_id: id.nullable().default(null),
  system_use_decision: systemUseDecisionReference,
  opened_at: timestamp,
  expires_at: timestamp,
});

export const modelCallOpenRecord = modelCallBinding
  .extend({
    state: z.literal('open'),
    outcome: z.literal('indeterminate'),
    provider_disclosure: z.literal('possible'),
    completed_at: z.null(),
    served_id: z.null(),
    output_digest: z.null(),
    failure_reason: z.null(),
  })
  .strict()
  .refine((record) => record.opened_at <= record.expires_at, {
    path: ['expires_at'],
    message: 'model call expires before it opens',
  });

const completedOutputCall = modelCallBinding.extend({
  state: z.literal('terminal'),
  provider_disclosure: z.literal('confirmed'),
  completed_at: timestamp,
  served_id: modelId,
  output_digest: hexDigest,
  failure_reason: z.null(),
});

export const modelCallAdmittedRecord = completedOutputCall
  .extend({ outcome: z.literal('admitted') })
  .strict();
export const modelCallWithheldRecord = completedOutputCall
  .extend({ outcome: z.literal('withheld') })
  .strict();
export const modelCallFailedRecord = modelCallBinding
  .extend({
    state: z.literal('terminal'),
    outcome: z.literal('failed'),
    provider_disclosure: z.enum(['possible', 'confirmed']),
    completed_at: timestamp,
    served_id: modelId.nullable(),
    output_digest: z.null(),
    failure_reason: modelCallFailureReason,
  })
  .strict()
  .superRefine((record, ctx) => {
    if (
      record.completed_at < record.opened_at ||
      (record.completed_at > record.expires_at && record.failure_reason !== 'selection-invalidated')
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['completed_at'],
        message: 'model call failure must complete within its attempt window',
      });
    }
    if (record.served_id !== null && record.provider_disclosure !== 'confirmed') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['provider_disclosure'],
        message: 'served-model evidence requires confirmed provider disclosure',
      });
    }
    if (
      ['malformed-response', 'tool-calls-refused', 'authorization-invalidated'].includes(record.failure_reason) &&
      record.provider_disclosure !== 'confirmed'
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['provider_disclosure'],
        message: 'post-response failure requires confirmed provider disclosure',
      });
    }
    if (record.failure_reason === 'tool-calls-refused' && record.served_id === null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['served_id'],
        message: 'tool-call refusal requires served-model evidence',
      });
    }
    if (
      record.failure_reason === 'system-use-invalidated' &&
      record.provider_disclosure === 'confirmed' &&
      record.served_id === null
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['served_id'],
        message: 'confirmed system-use invalidation requires served-response evidence',
      });
    }
    if (
      record.failure_reason === 'selection-invalidated' &&
      (record.provider_disclosure !== 'possible' || record.served_id !== null)
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['failure_reason'],
        message: 'selection invalidation requires possible disclosure and no served-model evidence',
      });
    }
  });

export const modelCallRecord = z.union([
  modelCallOpenRecord,
  modelCallAdmittedRecord,
  modelCallWithheldRecord,
  modelCallFailedRecord,
]);
export type ModelCallRecord = z.infer<typeof modelCallRecord>;
export type ModelCallOpenRecord = z.infer<typeof modelCallOpenRecord>;
export type ModelCallFailedRecord = z.infer<typeof modelCallFailedRecord>;

export const modelCallAdmissionRequest = z
  .object({
    call_id: id,
    output: modelOutputAdmissionRequest,
  })
  .strict();
export type ModelCallAdmissionRequest = z.infer<typeof modelCallAdmissionRequest>;

export const modelCallAdmission = z
  .object({
    kind: z.literal('model_call_admission'),
    call_id: id,
    decision: modelOutputAdmission,
    release: outputReleaseReference.nullable().default(null),
  })
  .strict();
export type ModelCallAdmission = z.infer<typeof modelCallAdmission>;

export const modelCallFailureRequest = z
  .object({
    call_id: id,
    turn_id: id,
    selection_id: id,
    projection_digest: hexDigest,
    failure_reason: modelCallReportableFailureReason,
    provider_disclosure: z.enum(['possible', 'confirmed']),
    served_id: modelId.nullable(),
  })
  .strict()
  .superRefine((request, ctx) => {
    if (request.served_id !== null && request.provider_disclosure !== 'confirmed') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['provider_disclosure'],
        message: 'served-model evidence requires confirmed provider disclosure',
      });
    }
    if (
      ['malformed-response', 'tool-calls-refused', 'authorization-invalidated'].includes(request.failure_reason) &&
      request.provider_disclosure !== 'confirmed'
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['provider_disclosure'],
        message: 'post-response failure requires confirmed provider disclosure',
      });
    }
    if (request.failure_reason === 'tool-calls-refused' && request.served_id === null) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['served_id'],
        message: 'tool-call refusal requires served-model evidence',
      });
    }
    if (
      request.failure_reason === 'system-use-invalidated' &&
      request.provider_disclosure === 'confirmed' &&
      request.served_id === null
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['served_id'],
        message: 'confirmed system-use invalidation requires served-response evidence',
      });
    }
  });
export type ModelCallFailureRequest = z.infer<typeof modelCallFailureRequest>;

/** Access-chain evidence contains lifecycle metadata and admission digests, never prompts, output, or errors. */
export const modelCallAccessEvidence = z.union([modelCallOpenRecord, modelCallFailedRecord, modelCallAdmission]);
export type ModelCallAccessEvidence = z.infer<typeof modelCallAccessEvidence>;
