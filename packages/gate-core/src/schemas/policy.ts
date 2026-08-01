// SPDX-License-Identifier: AGPL-3.0-only
/** Versioned deterministic policy contracts — spec §4 and ADR-001. */
import { z } from 'zod';

import { classToken, id, integer, jsonScalar } from './common.js';
import { interventionContract } from './intervention.js';
import { counterName, gate, screeningSignal, uxClass, verdict } from './ruling.js';

type PolicyScalar = string | number | boolean | null;

export type PolicyMatcher =
  | { kind: 'always' }
  | {
      kind: 'field';
      source: 'proposal' | 'mandate' | 'context';
      path: string[];
      operator: 'exists' | 'eq' | 'ne' | 'lte' | 'gte' | 'contains';
      value?: PolicyScalar;
    }
  | { kind: 'counter'; counter: z.infer<typeof counterName>; operator: 'would-exceed' | 'gte'; value?: number }
  | { kind: 'signal'; signal: z.infer<typeof screeningSignal>['signal']; min_confidence_pct: number }
  | { kind: 'pattern'; event: 'escalation' | 'timeout' | 'override'; window_ms: number; gte: number }
  | { kind: 'all'; matchers: PolicyMatcher[] }
  | { kind: 'any'; matchers: PolicyMatcher[] }
  | { kind: 'not'; matcher: PolicyMatcher };

export const policyMatcher: z.ZodType<PolicyMatcher> = z.lazy(() =>
  z.union([
    z.object({ kind: z.literal('always') }).strict(),
    z
      .object({
        kind: z.literal('field'),
        source: z.enum(['proposal', 'mandate', 'context']),
        path: z.array(z.string().min(1)).min(1),
        operator: z.enum(['exists', 'eq', 'ne', 'lte', 'gte', 'contains']),
        value: jsonScalar.optional(),
      })
      .strict()
      .superRefine((matcher, ctx) => {
        if (matcher.operator === 'exists' && typeof matcher.value !== 'boolean') {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['value'], message: 'exists requires a boolean value' });
        }
        if (matcher.operator !== 'exists' && matcher.value === undefined) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['value'], message: `${matcher.operator} requires a value` });
        }
      }),
    z
      .object({
        kind: z.literal('counter'),
        counter: counterName,
        operator: z.enum(['would-exceed', 'gte']),
        value: integer.optional(),
      })
      .strict()
      .superRefine((matcher, ctx) => {
        if (matcher.operator === 'gte' && matcher.value === undefined) {
          ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['value'], message: 'gte requires a value' });
        }
        if (matcher.operator === 'would-exceed' && matcher.value !== undefined) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['value'],
            message: 'would-exceed reads the declared counter limit and takes no value',
          });
        }
      }),
    z
      .object({
        kind: z.literal('signal'),
        signal: screeningSignal.shape.signal,
        min_confidence_pct: integer.min(0).max(100),
      })
      .strict(),
    z
      .object({
        kind: z.literal('pattern'),
        event: z.enum(['escalation', 'timeout', 'override']),
        window_ms: integer.min(1),
        gte: integer.min(1),
      })
      .strict(),
    z.object({ kind: z.literal('all'), matchers: z.array(policyMatcher).min(1) }).strict(),
    z.object({ kind: z.literal('any'), matchers: z.array(policyMatcher).min(1) }).strict(),
    z.object({ kind: z.literal('not'), matcher: policyMatcher }).strict(),
  ]),
);

export function matcherUsesSignal(matcher: PolicyMatcher): boolean {
  if (matcher.kind === 'signal') return true;
  if (matcher.kind === 'all' || matcher.kind === 'any') return matcher.matchers.some(matcherUsesSignal);
  if (matcher.kind === 'not') return matcherUsesSignal(matcher.matcher);
  return false;
}

export const policyRule = z
  .object({
    id,
    priority: integer,
    gate,
    matcher: policyMatcher,
    verdict,
    ux_class: uxClass,
    reason_template: z.string().min(1),
    intervention_contract: interventionContract.optional(),
    tool_request_class: z.enum(['inadmissible-with-fallback', 'new-tool-privilege-recipient-purpose']).optional(),
    screening_required: z.boolean().optional(),
  })
  .strict();

export type PolicyRule = z.infer<typeof policyRule>;

export const escalationPatternPolicy = z
  .object({
    window_ms: integer.min(1),
    escalation_count: integer.min(1),
    timeout_count: integer.min(1),
    override_count: integer.min(1),
    consequence: z.literal('narrow-pending-reauthorization'),
  })
  .strict();

export const policySet = z
  .object({
    policy_version: z.string().min(1),
    action_class: classToken.optional(),
    ordering: z.literal('deny-escalate-allow-then-priority'),
    default_escalation_contract: interventionContract,
    escalation_pattern: escalationPatternPolicy,
    rules: z.array(policyRule).min(1),
  })
  .strict()
  .superRefine((set, ctx) => {
    const ids = set.rules.map((rule) => rule.id);
    if (new Set(ids).size !== ids.length) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['rules'], message: 'policy rule ids must be unique' });
    }
    for (const [index, rule] of set.rules.entries()) {
      if (rule.verdict === 'escalate' && rule.intervention_contract === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rules', index, 'intervention_contract'],
          message: 'an escalating rule must carry the six intervention-contract fields',
        });
      }
      if (rule.verdict === 'escalate' && rule.ux_class !== 'stop') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rules', index, 'ux_class'],
          message: 'an escalating rule must use the Stop UX class',
        });
      }
      if (rule.verdict !== 'escalate' && rule.intervention_contract !== undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rules', index, 'intervention_contract'],
          message: 'only an escalating rule may carry an intervention contract',
        });
      }
      if (rule.verdict === 'allow' && rule.ux_class === 'stop') {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rules', index, 'ux_class'],
          message: 'an allowing rule cannot use the Stop UX class',
        });
      }
      if (rule.verdict === 'allow' && matcherUsesSignal(rule.matcher)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['rules', index, 'matcher'],
          message: 'a screening signal can never be a path to allow',
        });
      }
    }
  });

export type PolicySet = z.infer<typeof policySet>;
