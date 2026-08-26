// SPDX-License-Identifier: MIT
import type { RuleProposalResult } from 'gate-core/offline-safe';

import type {
  BoundedCaseResult,
  GateObservation,
  InterventionObservation,
  ScenarioContext,
} from './types.js';
import type { ProductionHarness } from './productionHarness.js';

export function gateObservation(result: RuleProposalResult): GateObservation {
  return {
    name: result.ruling.gate,
    verdict: result.ruling.verdict,
    matched_rule_id: result.ruling.matched_rule_id,
    ux_class: result.ruling.ux_class,
  };
}

export function interventionObservation(
  harness: ProductionHarness,
  escalationId: string | null,
): InterventionObservation | null {
  if (escalationId === null) return null;
  const escalation = harness.store.snapshot().escalations.get(escalationId);
  if (escalation === undefined) throw new Error(`executor lost escalation ${escalationId}`);
  return {
    trigger: escalation.contract.trigger_and_state.trigger,
    eligible_role: escalation.contract.decision_and_route.eligible_role,
    permitted_dispositions: [...escalation.contract.permitted_dispositions],
    terminal_disposition: escalation.terminal_disposition,
  };
}

export function boundedResult(
  context: ScenarioContext,
  fields: Omit<BoundedCaseResult, 'evidence_id' | 'case_id' | 'class' | 'lane_slot' | 'selected_card' | 'coverage'>,
): BoundedCaseResult {
  return {
    evidence_id: `m6:${context.row.id}:${context.laneSlot}`,
    case_id: context.row.id,
    class: context.row.class,
    lane_slot: context.laneSlot,
    selected_card: context.selectedCard,
    coverage: context.row.coverage,
    ...fields,
  };
}
