// SPDX-License-Identifier: AGPL-3.0-only
/** Pure fail-closed policy evaluation with deterministic verdict composition. */
import type {
  CounterName,
  FrozenProposal,
  Gate,
  InterventionContract,
  Mandate,
  PatternEvent,
  PolicyMatcher,
  PolicyRule,
  PolicySet,
  ScreeningSignal,
} from './schemas/index.js';

export const AUTHORITY_DEFECTS = [
  'missing-mandate',
  'expired-mandate',
  'revoked-mandate',
  'suspended-mandate',
  'invalid-mandate-binding',
  'broadened-request',
  'substituted-model',
  'substituted-service',
  'stale-policy',
  'stale-card',
  'replayed-ruling',
  'proposal-mismatch',
] as const;
export type AuthorityDefect = (typeof AUTHORITY_DEFECTS)[number];

export interface CounterEvaluation {
  readonly current: number;
  readonly delta: number;
  readonly limit: number | null;
}

export interface EvaluationContext {
  readonly gate: Gate;
  readonly proposal: FrozenProposal;
  readonly mandate: Mandate | undefined;
  readonly context: Readonly<Record<string, unknown>>;
  readonly counters: Readonly<Partial<Record<CounterName, CounterEvaluation>>>;
  readonly signals: readonly ScreeningSignal[];
  readonly screeningPerformed: boolean;
  readonly patternEvents: readonly PatternEvent[];
  readonly now: string;
  readonly authorityDefects: readonly AuthorityDefect[];
  readonly reauthorizationRequired?: boolean;
}

export interface EvaluationResult {
  readonly verdict: 'allow' | 'deny' | 'escalate';
  readonly uxClass: 'silent' | 'flag' | 'stop';
  readonly matchedRuleId: string | null;
  readonly reason: string;
  readonly interventionContract: InterventionContract | null;
}

function ownPath(root: unknown, path: readonly string[]): { found: boolean; value: unknown } {
  let value = root;
  for (const segment of path) {
    if (typeof value !== 'object' || value === null || !Object.prototype.hasOwnProperty.call(value, segment)) {
      return { found: false, value: undefined };
    }
    value = (value as Record<string, unknown>)[segment];
  }
  return { found: true, value };
}

function compareField(actual: unknown, matcher: Extract<PolicyMatcher, { kind: 'field' }>): boolean {
  const expected = matcher.value;
  switch (matcher.operator) {
    case 'exists':
      return actual !== undefined === expected;
    case 'eq':
      return Object.is(actual, expected);
    case 'ne':
      return !Object.is(actual, expected);
    case 'lte':
      return typeof actual === 'number' && typeof expected === 'number' && actual <= expected;
    case 'gte':
      return typeof actual === 'number' && typeof expected === 'number' && actual >= expected;
    case 'contains':
      if (Array.isArray(actual)) return actual.some((value) => Object.is(value, expected));
      return typeof actual === 'string' && typeof expected === 'string' && actual.includes(expected);
  }
}

export function evaluateMatcher(matcher: PolicyMatcher, input: EvaluationContext): boolean {
  switch (matcher.kind) {
    case 'always':
      return true;
    case 'field': {
      const source = matcher.source === 'proposal' ? input.proposal : matcher.source === 'mandate' ? input.mandate : input.context;
      const resolved = ownPath(source, matcher.path);
      if (matcher.operator === 'exists') return resolved.found === matcher.value;
      return resolved.found && compareField(resolved.value, matcher);
    }
    case 'counter': {
      const counter = input.counters[matcher.counter];
      if (counter === undefined) return false;
      if (matcher.operator === 'would-exceed') {
        return counter.limit !== null && counter.current + counter.delta > counter.limit;
      }
      return matcher.value !== undefined && counter.current >= matcher.value;
    }
    case 'signal':
      return input.signals.some(
        (signal) => signal.signal === matcher.signal && signal.confidence_pct >= matcher.min_confidence_pct,
      );
    case 'pattern': {
      const now = Date.parse(input.now);
      const earliest = now - matcher.window_ms;
      const count = input.patternEvents.filter(
        (event) => event.kind === matcher.event && Date.parse(event.at) >= earliest && Date.parse(event.at) <= now,
      ).length;
      return count >= matcher.gte;
    }
    case 'all':
      return matcher.matchers.every((child) => evaluateMatcher(child, input));
    case 'any':
      return matcher.matchers.some((child) => evaluateMatcher(child, input));
    case 'not':
      return !evaluateMatcher(matcher.matcher, input);
  }
}

const VERDICT_RANK: Readonly<Record<PolicyRule['verdict'], number>> = { deny: 3, escalate: 2, allow: 1 };

function compareRules(left: PolicyRule, right: PolicyRule): number {
  return (
    VERDICT_RANK[right.verdict] - VERDICT_RANK[left.verdict] ||
    right.priority - left.priority ||
    left.id.localeCompare(right.id)
  );
}

export function evaluatePolicy(policy: PolicySet, input: EvaluationContext): EvaluationResult {
  if (input.authorityDefects.length > 0) {
    const defect = [...input.authorityDefects].sort()[0] as AuthorityDefect;
    return {
      verdict: 'deny',
      uxClass: 'stop',
      matchedRuleId: `authority:${defect}`,
      reason: `Defective authority: ${defect}.`,
      interventionContract: null,
    };
  }

  if (input.reauthorizationRequired === true) {
    return {
      verdict: 'escalate',
      uxClass: 'stop',
      matchedRuleId: 'default:model-card-reconfirmation',
      reason: 'The pinned model card was superseded and requires principal re-confirmation.',
      interventionContract: policy.default_escalation_contract,
    };
  }

  const matches = policy.rules
    .filter((rule) => rule.gate === input.gate && evaluateMatcher(rule.matcher, input))
    .sort(compareRules);
  const winner = matches[0];
  if (winner === undefined) {
    return {
      verdict: 'escalate',
      uxClass: 'stop',
      matchedRuleId: null,
      reason: 'No policy rule matched the consequential proposal.',
      interventionContract: policy.default_escalation_contract,
    };
  }
  if (winner.verdict === 'allow' && input.signals.length > 0) {
    return {
      verdict: 'escalate',
      uxClass: 'stop',
      matchedRuleId: 'default:screening-signal',
      reason: 'A screening signal cannot authorize; human review is required.',
      interventionContract: policy.default_escalation_contract,
    };
  }
  if (winner.verdict === 'allow' && winner.screening_required === true && !input.screeningPerformed) {
    return {
      verdict: 'escalate',
      uxClass: 'stop',
      matchedRuleId: 'default:required-screening-missing',
      reason: 'A required screening check is unavailable.',
      interventionContract: policy.default_escalation_contract,
    };
  }
  return {
    verdict: winner.verdict,
    uxClass: winner.ux_class,
    matchedRuleId: winner.id,
    reason: winner.reason_template,
    interventionContract: winner.intervention_contract ?? null,
  };
}

export function escalationPatternRequiresNarrowing(
  policy: PolicySet,
  events: readonly PatternEvent[],
  mandateId: string,
  now: string,
): boolean {
  const earliest = Date.parse(now) - policy.escalation_pattern.window_ms;
  const recent = events.filter(
    (event) => event.mandate_id === mandateId && Date.parse(event.at) >= earliest && Date.parse(event.at) <= Date.parse(now),
  );
  const count = (kind: PatternEvent['kind']) => recent.filter((event) => event.kind === kind).length;
  return (
    count('escalation') >= policy.escalation_pattern.escalation_count ||
    count('timeout') >= policy.escalation_pattern.timeout_count ||
    count('override') >= policy.escalation_pattern.override_count
  );
}
