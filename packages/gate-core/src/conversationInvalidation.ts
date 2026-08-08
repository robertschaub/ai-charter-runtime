// SPDX-License-Identifier: AGPL-3.0-only
/** Shared M5.10 eager invalidations for authority and conversation-currentness changes. */
import type { OutputReleaseRecord, WalOp } from './schemas/index.js';
import type { WorldState } from './state.js';

function activeCaseRuling(
  state: WorldState,
  caseId: string,
  ruling: WorldState['rulings'] extends Map<string, infer T> ? T : never,
): boolean {
  if (ruling.status !== 'issued') return false;
  const selection = state.modelSelections.get(ruling.binding.selection_id);
  return selection?.case_id === caseId;
}

/** Eager invalidation paired with every active-case store mutation. */
export function conversationMutationInvalidationOps(
  state: WorldState,
  caseId: string,
  reason: string,
  at: string,
  excludeReleaseId?: string,
  excludeRulingId?: string,
): WalOp[] {
  const ops: WalOp[] = [];
  for (const ruling of state.rulings.values()) {
    if (!activeCaseRuling(state, caseId, ruling) || ruling.ruling_id === excludeRulingId) continue;
    ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason });
    for (const reservation of ruling.counter_reservations) {
      if (state.reservations.get(reservation.id)?.state === 'reserved') {
        ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason });
      }
    }
  }
  for (const release of state.outputReleases.values()) {
    if (release.case_id !== caseId || release.state !== 'issued' || release.release_id === excludeReleaseId) continue;
    ops.push({ op: 'output_release.invalidate', release_id: release.release_id, reason, changed_at: at });
  }
  for (const intake of state.proposalIntakes.values()) {
    if (intake.case_id !== caseId || intake.state !== 'issued') continue;
    ops.push({
      op: 'proposal_intake.invalidate',
      proposal_intake_id: intake.proposal_intake_id,
      reason: 'conversation-changed',
      changed_at: at,
    });
  }
  return ops;
}

export function outputReleaseInvalidationOps(
  state: WorldState,
  predicate: (release: OutputReleaseRecord) => boolean,
  reason: string,
  at: string,
): WalOp[] {
  return [...state.outputReleases.values()]
    .filter((release) => release.state === 'issued' && predicate(release))
    .map((release) => ({
      op: 'output_release.invalidate' as const,
      release_id: release.release_id,
      reason,
      changed_at: at,
    }));
}

export function proposalIntakeInvalidationOps(
  state: WorldState,
  predicate: (intake: WorldState['proposalIntakes'] extends Map<string, infer T> ? T : never) => boolean,
  reason: 'binding-invalidated' | 'conversation-changed',
  at: string,
): WalOp[] {
  return [...state.proposalIntakes.values()]
    .filter((intake) => intake.state === 'issued' && predicate(intake))
    .map((intake) => ({
      op: 'proposal_intake.invalidate' as const,
      proposal_intake_id: intake.proposal_intake_id,
      reason,
      changed_at: at,
    }));
}
