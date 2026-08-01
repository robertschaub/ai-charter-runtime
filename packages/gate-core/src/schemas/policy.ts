// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Policy rule — spec §4.
 *
 * Policy files are YAML, versioned in git; the ruling records the policy version and the
 * policy content digest. Default for any unmatched consequential proposal: escalate (fail
 * closed); defective authority: deny.
 *
 * The matcher is a discriminated placeholder: M1 fixes the rule envelope, M2 fills in the
 * match language over proposal / mandate / counters / signals.
 */
import { z } from 'zod';

import { classToken, id } from './common.js';
import { interventionContract } from './intervention.js';
import { gate, uxClass, verdict } from './ruling.js';

/**
 * M2 adds members to this union. It is discriminated from the start so a later matcher
 * kind is an addition rather than a breaking reshape, and so an unrecognized matcher fails
 * validation instead of being silently ignored.
 */
export const policyMatcher = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('placeholder'),
    note: z.string().min(1),
  }),
]);

export type PolicyMatcher = z.infer<typeof policyMatcher>;

export const policyRule = z.object({
  id,
  gate,
  matcher: policyMatcher,
  verdict,
  ux_class: uxClass,
  reason_template: z.string().min(1),
  /** Required for escalations: an escalation without all six fields refuses to fire. */
  intervention_contract: interventionContract.optional(),
  /** Spec §5: the policy file marks which class a tool request falls into. */
  tool_request_class: z.enum(['inadmissible-with-fallback', 'new-tool-privilege-recipient-purpose']).optional(),
  /** ADR-005 §6: where screening is required, a missing check escalates. */
  screening_required: z.boolean().optional(),
});

export type PolicyRule = z.infer<typeof policyRule>;

export const policySet = z
  .object({
    policy_version: z.string().min(1),
    action_class: classToken.optional(),
    rules: z.array(policyRule).min(1),
  })
  .superRefine((set, ctx) => {
    for (const [index, rule] of set.rules.entries()) {
      if (rule.verdict === 'escalate' && rule.intervention_contract === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rules', index, 'intervention_contract'],
          message: 'an escalating rule must carry the six intervention-contract fields (ADR-001 §7)',
        });
      }
    }
  });

export type PolicySet = z.infer<typeof policySet>;
