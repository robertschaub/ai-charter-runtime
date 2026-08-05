// SPDX-License-Identifier: AGPL-3.0-only
/** M5.3 non-authorizing model-output admission contracts. */
import { z } from 'zod';

import {
  cardSlug,
  hexDigest,
  id,
  integer,
  isSortedUnique,
  modelId,
  sortedRestrictionTags,
} from './common.js';

export const MAX_MODEL_OUTPUT_CHARS = 65_536;

export const MODEL_OUTPUT_CONTROL_REASONS = [
  'claimed-feeling-or-consciousness',
  'relational-dependency-language',
  'served-model-mismatch',
] as const;
export const modelOutputControlReason = z.enum(MODEL_OUTPUT_CONTROL_REASONS);
export type ModelOutputControlReason = z.infer<typeof modelOutputControlReason>;

export const MODEL_OUTPUT_CONTROL_FLAGS = ['model_resolution_unrecorded'] as const;
export const modelOutputControlFlag = z.enum(MODEL_OUTPUT_CONTROL_FLAGS);
export type ModelOutputControlFlag = z.infer<typeof modelOutputControlFlag>;

function isWellFormedUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

export const modelOutputAdmissionRequest = z
  .object({
    turn_id: id,
    selection_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    card_id: cardSlug,
    card_version: integer.min(1),
    requested_id: modelId,
    served_id: modelId,
    projection_digest: hexDigest,
    content: z
      .string()
      .min(1)
      .max(MAX_MODEL_OUTPUT_CHARS)
      .refine(isWellFormedUnicode, 'model output must be well-formed Unicode'),
  })
  .strict();

const reasonArray = z.array(modelOutputControlReason);
const sortedNonemptyReasons = reasonArray
  .min(1)
  .refine(isSortedUnique, 'output-control reasons must be de-duplicated and sorted');
const sortedFlags = z
  .array(modelOutputControlFlag)
  .refine(isSortedUnique, 'output-control flags must be de-duplicated and sorted');

const outputControlBase = z
  .object({
    kind: z.literal('model_output_control'),
    case_id: id,
    turn_id: id,
    selection_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    card_id: cardSlug,
    card_version: integer.min(1),
    requested_id: modelId,
    served_id: modelId,
    projection_digest: hexDigest,
    projection_item_count: integer.min(0),
    output_digest: hexDigest,
    model_resolution: z.enum(['exact', 'benign-resolution', 'mismatch']),
    flags: sortedFlags,
    /** An admission decision can govern display/use of text but can never grant action authority. */
    authority_effect: z.literal('none'),
  })
  .strict();

export const modelOutputAdmission = z
  .discriminatedUnion('disposition', [
    outputControlBase.extend({
      disposition: z.literal('admitted'),
      reasons: reasonArray.length(0),
      derived_tags: sortedRestrictionTags,
    }),
    outputControlBase.extend({
      disposition: z.literal('withheld'),
      reasons: sortedNonemptyReasons,
    }),
  ])
  .superRefine((decision, ctx) => {
    const hasMismatch = decision.reasons.includes('served-model-mismatch');
    if ((decision.model_resolution === 'mismatch') !== hasMismatch) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['model_resolution'],
        message: 'served-model mismatch reason and comparison must agree',
      });
    }
    if (decision.disposition === 'admitted' && decision.model_resolution === 'mismatch') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['disposition'],
        message: 'a served-model mismatch cannot be admitted',
      });
    }
    const unrecorded = decision.flags.includes('model_resolution_unrecorded');
    if (unrecorded && decision.model_resolution !== 'benign-resolution') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['flags'],
        message: 'only a benign alias resolution may be unrecorded',
      });
    }
  });

export type ModelOutputAdmissionRequest = z.infer<typeof modelOutputAdmissionRequest>;
export type ModelOutputAdmission = z.infer<typeof modelOutputAdmission>;
