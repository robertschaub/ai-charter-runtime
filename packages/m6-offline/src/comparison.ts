// SPDX-License-Identifier: MIT
import { digestFor } from 'gate-core/offline-safe';

import { loadProviderFixture } from './catalog.js';
import type { BoundedCaseResult, ComparisonProjection, PairComparison } from './types.js';

export function comparisonProjection(result: BoundedCaseResult): ComparisonProjection {
  return {
    gates: result.gates,
    intervention: result.intervention,
    commitment_state: result.commitment_state,
    effect_count: result.effect_count,
    failure_class: result.failure_class,
    containment_class: result.containment_class,
    coverage: result.coverage,
  };
}

function assertion(result: BoundedCaseResult, name: string): boolean | number | string | null | undefined {
  return result.observed_assertions.find((entry) => entry.name === name)?.observed;
}

function assertProviderSpecific(result: BoundedCaseResult): void {
  if (result.case_id !== 'beat-20' || (result.lane_slot !== 'lane-0' && result.lane_slot !== 'lane-1')) {
    throw new Error('provider-specific comparison is permitted only for beat-20');
  }
  const fixture = loadProviderFixture() as {
    lanes: readonly { lane_slot: string; card_binding: unknown; expected: { mandate_permission: string; submit_verdict: string; matched_rule_id: string; disclosure_boundary: string; containment_state: string } }[];
  };
  const expected = fixture.lanes.find((lane) => lane.lane_slot === result.lane_slot);
  const expectedCard = expected?.card_binding as BoundedCaseResult['selected_card'];
  if (expected === undefined || result.selected_card === null || expectedCard === null ||
    result.selected_card.card_id !== expectedCard.card_id || result.selected_card.card_version !== expectedCard.card_version ||
    result.selected_card.card_digest !== expectedCard.card_digest || result.selected_card.requested_id !== expectedCard.requested_id) {
    throw new Error('beat-20 card binding does not match its fixture');
  }
  const submit = result.gates.find((gate) => gate.name === 'submit');
  const actualContainment = result.containment_class === 'stopped-before-disclosure' ? 'stopped' : result.containment_class;
  if (
    assertion(result, 'mandate_permission') !== expected.expected.mandate_permission ||
    assertion(result, 'disclosure_boundary') !== expected.expected.disclosure_boundary ||
    submit?.verdict !== expected.expected.submit_verdict || submit.matched_rule_id !== expected.expected.matched_rule_id ||
    actualContainment !== expected.expected.containment_state ||
    result.effect_count !== 0 || result.commitment_state !== (result.lane_slot === 'lane-0' ? 'none' : 'blocked')
  ) throw new Error(`beat-20 ${result.lane_slot} diverged from its exact provider fixture`);
}

export function comparePair(lane0: BoundedCaseResult, lane1: BoundedCaseResult, mode: 'invariant' | 'provider_specific'): PairComparison {
  if (lane0.case_id !== lane1.case_id || lane0.lane_slot !== 'lane-0' || lane1.lane_slot !== 'lane-1') throw new Error('comparison pair binding mismatch');
  const lane0Digest = digestFor('m6-offline-outcome', comparisonProjection(lane0));
  const lane1Digest = digestFor('m6-offline-outcome', comparisonProjection(lane1));
  if (mode === 'invariant') {
    if (lane0Digest !== lane1Digest) throw new Error(`${lane0.case_id} violated its invariant outcome`);
    return { case_id: lane0.case_id, mode, lane_0_digest: lane0Digest, lane_1_digest: lane1Digest, outcome_equal: true, status: 'pass', reason: 'invariant_outcome' };
  }
  assertProviderSpecific(lane0);
  assertProviderSpecific(lane1);
  return { case_id: lane0.case_id, mode, lane_0_digest: lane0Digest, lane_1_digest: lane1Digest, outcome_equal: lane0Digest === lane1Digest, status: 'pass', reason: 'expected_provider_permission_difference' };
}
