// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-008 — authorization-owned system-use decision and bounded references. */
import { z } from 'zod';

import {
  cardSlug,
  hexDigest,
  id,
  integer,
  modelRole,
  restrictionTagSet,
  timestamp,
  worldId,
} from './common.js';

export const SYSTEM_USE_DECISION_STATUSES = [
  'proposed',
  'approved',
  'approved_with_conditions',
  'rejected',
  'superseded',
  'suspended',
  'withdrawn',
  'expired',
] as const;
export const systemUseDecisionStatus = z.enum(SYSTEM_USE_DECISION_STATUSES);
export type SystemUseDecisionStatus = z.infer<typeof systemUseDecisionStatus>;

export const SYSTEM_USE_EVIDENCE_DEPTHS = [
  'documented',
  'evidence_observed',
  'implementation_checked',
  'effectiveness_tested',
  'not_assessed',
] as const;
export const systemUseEvidenceDepth = z.enum(SYSTEM_USE_EVIDENCE_DEPTHS);

export const SYSTEM_USE_PROVENANCE = ['synthetic_fixture', 'self_declared', 'probe_tested'] as const;
export const systemUseProvenance = z.enum(SYSTEM_USE_PROVENANCE);

const uniqueSortedStrings = z
  .array(z.string().min(1))
  .refine((values) => new Set(values).size === values.length, 'values must be unique')
  .refine(
    (values) => values.every((value, index) => index === 0 || (values[index - 1] as string) < value),
    'values must use deterministic lexical ordering',
  );

export const systemUseModelCardBinding = z
  .object({
    card_id: cardSlug,
    card_version: integer.min(1),
    card_digest: hexDigest,
    roles: z
      .array(modelRole)
      .min(1)
      .refine((values) => new Set(values).size === values.length, 'roles must be unique')
      .refine(
        (values) => values.every((value, index) => index === 0 || (values[index - 1] as string) < value),
        'roles must use deterministic lexical ordering',
      ),
  })
  .strict();

export const systemUseEvidenceRef = z
  .object({
    type: z.enum([
      'release-risk-assessment',
      'impact-assessment',
      'testing-and-validation',
      'monitoring-and-response',
    ]),
    ref: z.string().min(1),
    digest: hexDigest.optional(),
    provenance: systemUseProvenance,
    evidence_depth: systemUseEvidenceDepth,
    as_of: z.string().date(),
    limitations: uniqueSortedStrings,
  })
  .strict();

export const systemUseCondition = z.object({ id, kind: z.literal('hard_precondition') }).strict();

export const systemUseDecisionRecord = z
  .object({
    schema: z.literal('our-ai-charter/system-use-decision@1'),
    decision_id: id,
    version: integer.min(1),
    world_id: worldId,
    use_case_id: id,
    subject: z
      .object({
        system_id: id,
        configuration_digest: hexDigest,
        policy_version: z.string().min(1),
        model_cards: z
          .array(systemUseModelCardBinding)
          .min(1)
          .refine(
            (values) =>
              values.every(
                (value, index) =>
                  index === 0 ||
                  `${values[index - 1]?.card_id}\u0000${values[index - 1]?.card_version}` <
                    `${value.card_id}\u0000${value.card_version}`,
              ),
            'model-card bindings must be uniquely sorted by card id and version',
          ),
        data_classes: restrictionTagSet,
        jurisdictions: uniqueSortedStrings,
      })
      .strict(),
    purpose: z
      .object({
        need: z.string().min(1),
        expected_outcome: z.string().min(1),
        success_measures: uniqueSortedStrings,
        non_ai_or_less_harmful_alternative: z.string().min(1),
        affected_groups: uniqueSortedStrings,
      })
      .strict(),
    evidence_refs: z.array(systemUseEvidenceRef).min(1),
    decision: z
      .object({
        status: systemUseDecisionStatus,
        authority_role: id,
        basis_summary: z.string().min(1),
        conditions: z
          .array(systemUseCondition)
          .refine((values) => new Set(values.map((value) => value.id)).size === values.length, 'condition ids must be unique')
          .refine(
            (values) => values.every((value, index) => index === 0 || (values[index - 1]?.id as string) < value.id),
            'conditions must use deterministic id ordering',
          ),
        unresolved_findings: uniqueSortedStrings,
        residual_risk: z
          .object({ disposition: z.enum(['accepted', 'not_assessed']), authority_role: id })
          .strict(),
      })
      .strict()
      .superRefine((decision, ctx) => {
        if (decision.status === 'approved_with_conditions' && decision.conditions.length === 0) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['conditions'], message: 'conditional approval requires conditions' });
        }
      }),
    validity: z
      .object({
        effective_at: timestamp,
        expires_at: timestamp,
        review_cadence: z.string().min(1),
        redecision_triggers: uniqueSortedStrings,
      })
      .strict(),
    accountability: z
      .object({
        mission_owner_role: id,
        technical_owner_role: id,
        independent_challenger_role: z.union([id, z.literal('not_available_in_poc')]),
        remedy_owner_role: z.union([id, z.literal('not_available_in_poc')]),
      })
      .strict(),
    trace: z
      .object({
        record_digest: hexDigest,
        evidence_pack_ref: z.string().min(1),
        created_at: timestamp,
        supersedes: z.object({ decision_id: id, version: integer.min(1) }).strict().nullable(),
        challenge_route: z.string().min(1),
      })
      .strict(),
  })
  .strict()
  .superRefine((record, ctx) => {
    if (record.validity.effective_at > record.validity.expires_at) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['validity', 'expires_at'], message: 'decision expires before it is effective' });
    }
    if (record.trace.created_at > record.validity.expires_at) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['trace', 'created_at'], message: 'decision is created after expiry' });
    }
    if (record.trace.supersedes !== null && record.trace.supersedes.decision_id !== record.decision_id) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['trace', 'supersedes'], message: 'successor must retain the decision id' });
    }
  });
export type SystemUseDecisionRecord = z.infer<typeof systemUseDecisionRecord>;

export const systemUseConditionResult = z.object({ id, satisfied: z.boolean() }).strict();

export const systemUseDecisionReference = z
  .object({
    decision_id: id,
    version: integer.min(1),
    record_digest: hexDigest,
    status: z.enum(['approved', 'approved_with_conditions']),
    conditions: z.array(systemUseConditionResult),
  })
  .strict();
export type SystemUseDecisionReference = z.infer<typeof systemUseDecisionReference>;

export const systemUseDecisionBinding = systemUseDecisionReference.pick({
  decision_id: true,
  version: true,
  record_digest: true,
});
export type SystemUseDecisionBinding = z.infer<typeof systemUseDecisionBinding>;

const governanceDecision = z
  .object({
    decision_id: id,
    version: integer.min(1),
    record_digest: hexDigest,
    status: systemUseDecisionStatus,
    world_id: worldId,
    use_case_id: id,
    system_id: id,
    configuration_digest: hexDigest,
    policy_version: z.string().min(1),
    model_cards: z.array(systemUseModelCardBinding),
    data_classes: restrictionTagSet,
    jurisdictions: uniqueSortedStrings,
    evidence: z.array(
      z
        .object({
          type: systemUseEvidenceRef.shape.type,
          provenance: systemUseProvenance,
          evidence_depth: systemUseEvidenceDepth,
          as_of: z.string().date(),
          limitations: uniqueSortedStrings,
        })
        .strict(),
    ),
    conditions: z.array(systemUseConditionResult),
    effective_at: timestamp,
    expires_at: timestamp,
    review_cadence: z.string().min(1),
    redecision_triggers: uniqueSortedStrings,
    basis_summary: z.string().min(1),
    unresolved_finding_count: integer.min(0),
    accountability: systemUseDecisionRecord.innerType().shape.accountability,
    limitations: z.array(z.string().min(1)),
  })
  .strict();

export const systemUseGovernanceProjection = z.discriminatedUnion('currentness', [
  z.object({ currentness: z.literal('missing'), decision: z.null() }).strict(),
  z.object({ currentness: z.enum(['current', 'not-current']), decision: governanceDecision }).strict(),
]);
export type SystemUseGovernanceProjection = z.infer<typeof systemUseGovernanceProjection>;
