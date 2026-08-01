// SPDX-License-Identifier: AGPL-3.0-only
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { evaluatePolicy } from './evaluator.js';
import { loadPolicyFile } from './policyLoader.js';
import type { EvaluationContext } from './evaluator.js';
import type { FrozenProposal, Mandate, ScreeningSignal } from './schemas/index.js';

const POLICY_FILE = fileURLToPath(new URL('../policy/v1.yaml', import.meta.url));
const BUILD_DIGEST = 'b'.repeat(64);
const policy = loadPolicyFile(POLICY_FILE, BUILD_DIGEST).policy;

const proposal = {
  world_id: 'w-demo',
  proposed_action: 'Synthetic consequential action.',
} as FrozenProposal;
const mandate = { world_id: 'w-demo', action_class: 'grant-filing' } as Mandate;

function context(overrides: Partial<EvaluationContext> = {}): EvaluationContext {
  return {
    gate: 'commit',
    proposal,
    mandate,
    context: {},
    counters: {},
    signals: [],
    screeningPerformed: true,
    patternEvents: [],
    now: '2026-08-01T09:00:00.000Z',
    authorityDefects: [],
    ...overrides,
  };
}

function signal(): ScreeningSignal {
  return {
    kind: 'screening_signal',
    signal: 'scope_drift',
    confidence_pct: 1,
    rationale: 'Synthetic test signal.',
    model_id: 'screening-model',
    model_version_reported: 'screening-model-v1',
  };
}

describe('deterministic policy evaluator', () => {
  it('loads the checked-in policy with a stable digest and fixed ordering', () => {
    const first = loadPolicyFile(POLICY_FILE, BUILD_DIGEST);
    const second = loadPolicyFile(POLICY_FILE, BUILD_DIGEST);
    expect(first.policyContentDigest).toBe(second.policyContentDigest);
    expect(first.policy.ordering).toBe('deny-escalate-allow-then-priority');
  });

  it('defaults unmatched consequential work to Stop + escalate', () => {
    const result = evaluatePolicy(policy, context({ mandate: { ...mandate, action_class: 'unknown-action' } }));
    expect(result).toMatchObject({ verdict: 'escalate', uxClass: 'stop', matchedRuleId: null });
    expect(result.interventionContract).not.toBeNull();
  });

  it('makes every authority defect a deny before ordinary rules run', () => {
    for (const defect of [
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
    ] as const) {
      expect(evaluatePolicy(policy, context({ authorityDefects: [defect] }))).toMatchObject({
        verdict: 'deny',
        uxClass: 'stop',
        matchedRuleId: `authority:${defect}`,
      });
    }
  });

  it('never lets a screening signal reach an allow result', () => {
    const result = evaluatePolicy(policy, context({ signals: [signal()] }));
    expect(result).toMatchObject({ verdict: 'escalate', uxClass: 'stop' });
  });

  it('beat 1 allows a permitted registry retrieval as a silent trace', () => {
    expect(
      evaluatePolicy(
        policy,
        context({ gate: 'submit', mandate: { ...mandate, action_class: 'registry-read' } }),
      ),
    ).toMatchObject({ verdict: 'allow', uxClass: 'silent', matchedRuleId: 'allow-registry-read' });
  });

  it('beat 2 denies an inadmissible tool with fallback and escalates only genuinely new authority', () => {
    const inadmissible = evaluatePolicy(
      policy,
      context({ gate: 'authorize', context: { tool_request_class: 'inadmissible-with-fallback' } }),
    );
    expect(inadmissible).toMatchObject({ verdict: 'deny', uxClass: 'flag' });
    expect(inadmissible.interventionContract).toBeNull();

    const newAuthority = evaluatePolicy(
      policy,
      context({ gate: 'authorize', context: { tool_request_class: 'new-tool-privilege-recipient-purpose' } }),
    );
    expect(newAuthority).toMatchObject({ verdict: 'escalate', uxClass: 'stop' });
    expect(newAuthority.interventionContract?.permitted_dispositions).not.toContain('allow-within-scope');
    expect(newAuthority.interventionContract?.response_bound_and_default.safe_default).toMatchObject({
      kind: 'stop-remains',
      disposition: 'cancel',
      authority_basis: { kind: 'no-new-authority' },
    });
  });

  it('applies deny before escalate before allow, then priority and rule id', () => {
    const custom = {
      ...policy,
      rules: [
        {
          id: 'allow-high-priority',
          priority: 1000,
          gate: 'commit' as const,
          matcher: { kind: 'always' as const },
          verdict: 'allow' as const,
          ux_class: 'silent' as const,
          reason_template: 'allow',
        },
        {
          id: 'deny-low-priority',
          priority: -1000,
          gate: 'commit' as const,
          matcher: { kind: 'always' as const },
          verdict: 'deny' as const,
          ux_class: 'flag' as const,
          reason_template: 'deny',
        },
      ],
    };
    expect(evaluatePolicy(custom, context())).toMatchObject({ verdict: 'deny', matchedRuleId: 'deny-low-priority' });
  });
});
