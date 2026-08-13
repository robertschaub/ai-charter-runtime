// SPDX-License-Identifier: AGPL-3.0-only
/** M6.1 durable, metadata-only live-screening call contracts. */
import { z } from 'zod';

import { cardSlug, confidencePct, hexDigest, id, integer, modelId, timestamp, worldId } from './common.js';
import { modelCallReportableFailureReason } from './modelCall.js';
import { gate, SCREENING_SIGNALS, screeningSignal } from './ruling.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

export const SCREENING_RESPONSE_SCHEMA_ID = 'screening-signals@1' as const;
export const SCREENING_MAX_OUTPUT_BYTES = 65_536;
export const SCREENING_MAX_OUTPUT_TOKENS = 512;

export const screeningProviderSignal = z
  .object({
    signal: z.enum(SCREENING_SIGNALS),
    suspect_item_id: id.nullable(),
    confidence_pct: confidencePct,
    rationale: z.string().min(1).max(1_024),
  })
  .strict();

export const screeningProviderResponse = z
  .array(screeningProviderSignal)
  .max(16)
  .superRefine((signals, context) => {
    const pairs = new Set<string>();
    for (const [index, signal] of signals.entries()) {
      const key = `${signal.signal}\n${signal.suspect_item_id ?? ''}`;
      if (pairs.has(key)) {
        context.addIssue({
          code: z.ZodIssueCode.custom,
          path: [index],
          message: 'screening signal and suspect item pairs must be unique',
        });
      }
      pairs.add(key);
    }
  });
export type ScreeningProviderSignal = z.infer<typeof screeningProviderSignal>;

/** M6.1 always records the nullable suspect field; legacy fixture signals may still omit it. */
export const liveScreeningSignal = screeningSignal.extend({
  suspect_item_id: id.nullable(),
  rationale: z.string().min(1).max(1_024),
}).strict();

const screeningCallBinding = z.object({
  kind: z.literal('screening_call_lifecycle'),
  world_id: worldId,
  call_id: id,
  authorization_boot_id: id,
  case_id: id,
  proposal_id: id,
  proposal_run_id: id,
  proposal_hash: hexDigest,
  gate: gate.refine((value) => value === 'submit' || value === 'verify', 'screening gate must be submit or verify'),
  screening_role: z.literal('screening'),
  policy_version: z.string().min(1),
  policy_content_digest: hexDigest,
  evaluator_build_id: z.string().min(1),
  mandate_id: id,
  mandate_version: integer.min(1),
  card_id: cardSlug,
  card_version: integer.min(1),
  card_digest: hexDigest,
  card_key_id: id,
  requested_id: modelId,
  projection_digest: hexDigest,
  projection_item_count: integer.min(0),
  projection_item_ids: z.array(id),
  system_use_decision: systemUseDecisionReference,
  response_schema_id: z.literal(SCREENING_RESPONSE_SCHEMA_ID),
  response_schema_digest: hexDigest,
  max_output_tokens: z.literal(SCREENING_MAX_OUTPUT_TOKENS),
  tools_allowed: z.literal(false),
  opened_at: timestamp,
  expires_at: timestamp,
});

export const screeningCallOpenRecord = screeningCallBinding
  .extend({
    state: z.literal('open'),
    outcome: z.literal('indeterminate'),
    provider_disclosure: z.literal('possible'),
    completed_at: z.null(),
    served_id: z.null(),
    model_resolution: z.null(),
    output_digest: z.null(),
    failure_reason: z.null(),
    signals: z.array(screeningSignal).length(0),
  })
  .strict()
  .superRefine((record, context) => {
    if (record.opened_at > record.expires_at) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'screening call expires before opening' });
    }
    if (
      record.projection_item_count !== record.projection_item_ids.length ||
      new Set(record.projection_item_ids).size !== record.projection_item_ids.length
    ) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['projection_item_ids'], message: 'screening projection binding is inconsistent' });
    }
  });

export const screeningCallAdmittedRecord = screeningCallBinding
  .extend({
    state: z.literal('terminal'),
    outcome: z.literal('admitted'),
    provider_disclosure: z.literal('confirmed'),
    completed_at: timestamp,
    served_id: modelId,
    model_resolution: z.enum(['exact', 'benign-resolution']),
    output_digest: hexDigest,
    failure_reason: z.null(),
    signals: z.array(liveScreeningSignal).max(16),
  })
  .strict();

export const screeningCallFailedRecord = screeningCallBinding
  .extend({
    state: z.literal('terminal'),
    outcome: z.literal('failed'),
    provider_disclosure: z.enum(['possible', 'confirmed']),
    completed_at: timestamp,
    served_id: modelId.nullable(),
    model_resolution: z.enum(['exact', 'benign-resolution', 'mismatch']).nullable(),
    output_digest: hexDigest.nullable(),
    failure_reason: modelCallReportableFailureReason,
    signals: z.array(screeningSignal).length(0),
  })
  .strict()
  .superRefine((record, context) => {
    if (record.served_id !== null && record.provider_disclosure !== 'confirmed') {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['provider_disclosure'], message: 'served id requires confirmed disclosure' });
    }
    if (record.output_digest !== null && record.provider_disclosure !== 'confirmed') {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['output_digest'], message: 'output digest requires confirmed disclosure' });
    }
    if (['malformed-response', 'tool-calls-refused'].includes(record.failure_reason) && record.provider_disclosure !== 'confirmed') {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['provider_disclosure'], message: 'post-response failure requires confirmed disclosure' });
    }
    if (record.failure_reason === 'tool-calls-refused' && record.served_id === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['served_id'], message: 'tool-call refusal requires served-model evidence' });
    }
    if (record.failure_reason === 'system-use-invalidated' && record.provider_disclosure === 'confirmed' && record.served_id === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['served_id'], message: 'confirmed system-use invalidation requires served-response evidence' });
    }
  });

export const screeningCallRecord = z.union([
  screeningCallOpenRecord,
  screeningCallAdmittedRecord,
  screeningCallFailedRecord,
]);
export type ScreeningCallRecord = z.infer<typeof screeningCallRecord>;
export type ScreeningCallOpenRecord = z.infer<typeof screeningCallOpenRecord>;
export type ScreeningCallAdmittedRecord = z.infer<typeof screeningCallAdmittedRecord>;
export type ScreeningCallFailedRecord = z.infer<typeof screeningCallFailedRecord>;

export const screeningCallOutputRequest = z
  .object({
    content: z.string().min(1).refine((value) => Buffer.byteLength(value, 'utf8') <= SCREENING_MAX_OUTPUT_BYTES, 'screening output exceeds 64 KiB'),
    served_id: modelId,
  })
  .strict();
export type ScreeningCallOutputRequest = z.infer<typeof screeningCallOutputRequest>;

export const screeningCallFailureRequest = z
  .object({
    failure_reason: modelCallReportableFailureReason,
    provider_disclosure: z.enum(['possible', 'confirmed']),
    served_id: modelId.nullable(),
  })
  .strict()
  .superRefine((request, context) => {
    if (request.served_id !== null && request.provider_disclosure !== 'confirmed') {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['provider_disclosure'], message: 'served id requires confirmed disclosure' });
    }
    if (['malformed-response', 'tool-calls-refused', 'authorization-invalidated'].includes(request.failure_reason) && request.provider_disclosure !== 'confirmed') {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['provider_disclosure'], message: 'post-response failure requires confirmed disclosure' });
    }
    if (request.failure_reason === 'tool-calls-refused' && request.served_id === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['served_id'], message: 'tool-call refusal requires served-model evidence' });
    }
    if (request.failure_reason === 'system-use-invalidated' && request.provider_disclosure === 'confirmed' && request.served_id === null) {
      context.addIssue({ code: z.ZodIssueCode.custom, path: ['served_id'], message: 'confirmed system-use invalidation requires served-response evidence' });
    }
  });
export type ScreeningCallFailureRequest = z.infer<typeof screeningCallFailureRequest>;

/** Process/access projection: lifecycle metadata only; normalized signals remain authorization-side evidence. */
export const screeningCallTerminalProjection = z
  .object({
    kind: z.literal('screening_call_terminal'),
    call_id: id,
    proposal_id: id,
    proposal_run_id: id,
    gate: gate.refine((value) => value === 'submit' || value === 'verify'),
    state: z.literal('terminal'),
    outcome: z.enum(['admitted', 'failed']),
    provider_disclosure: z.enum(['possible', 'confirmed']),
    served_id: modelId.nullable(),
    output_digest: hexDigest.nullable(),
    failure_reason: modelCallReportableFailureReason.nullable(),
    completed_at: timestamp,
  })
  .strict();
export type ScreeningCallTerminalProjection = z.infer<typeof screeningCallTerminalProjection>;
