// SPDX-License-Identifier: AGPL-3.0-only
/** Observable expiry/timeout transitions; safety itself remains lazy at every decision. */
import { randomUUID } from 'node:crypto';

import { bindMandate, type IdFactory } from './authorizationCore.js';
import { escalationPatternRequiresNarrowing } from './evaluator.js';
import type { Keyring } from './keyring.js';
import type { LoadedPolicy } from './policyLoader.js';
import type { Disposition, GateRuling, Mandate, PatternEvent, RecordEntry, WalOp } from './schemas/index.js';
import { mandateVersionKey, type WorldState } from './state.js';
import { systemUseReferenceCurrent } from './systemUseDecision.js';
import type { TransactionActor, WalStore } from './walStore.js';

const defaultIds: IdFactory = { next: (prefix) => `${prefix}_${randomUUID()}` };

export interface SweepResult {
  readonly changed: boolean;
  readonly expiredRulings: number;
  readonly timedOutEscalations: number;
  readonly expiredMandates: number;
  readonly narrowedMandates: number;
}

function mandateBody(value: Mandate): Omit<Mandate, 'binding'> {
  const { binding: ignored, ...body } = value;
  void ignored;
  return body;
}

function chainIds(value: Mandate | undefined): string[] {
  if (value === undefined) return [];
  return [...new Set(value.authority_chain.flatMap((hop) => [hop.delegator, hop.delegate]))];
}

function timeoutRecord(
  state: WorldState,
  ruling: GateRuling,
  escalationId: string,
  defaultDisposition: Disposition,
  entryId: string,
  at: string,
): RecordEntry {
  const proposalId = state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : state.proposals.get(proposalId);
  if (proposal === undefined) throw new Error(`escalation ${escalationId} lost its frozen proposal`);
  const mandate = state.mandates.get(mandateVersionKey(ruling.binding.mandate_id, ruling.binding.mandate_version));
  return {
    world_id: state.worldId,
    entry_id: entryId,
    at,
    authenticated_actor: 'proc:authz',
    claimed_actor: { role: null },
    system_use_decision: ruling.binding.system_use_decision,
    system_use_current_at_record: systemUseReferenceCurrent(state, ruling.binding.system_use_decision, at),
    proposed_action: proposal.proposed_action,
    basis: [...proposal.material_inputs.map((item) => item.id), ...proposal.derived_claims.map((item) => item.id)],
    authority_chain: chainIds(mandate),
    admissibility_decision: { ruling_id: ruling.ruling_id, verdict: ruling.verdict },
    policy_model_version: {
      policy_version: ruling.policy_version,
      policy_content_digest: ruling.policy_content_digest,
      evaluator_build_id: ruling.evaluator_build_id,
      acting_model_requested_id: proposal.acting_model.requested_id,
      acting_model_served_id: proposal.acting_model.served_id,
    },
    commitment_and_effect: null,
    human_intervention_event: {
      event: 'human_intervention_event',
      escalation_id: escalationId,
      payload: {
        kind: 'escalation_timeout',
        applied_default: defaultDisposition,
        at,
      },
    },
    challenge_and_remedy: null,
  };
}

export async function runSweeper(
  store: WalStore,
  keyring: Keyring,
  policy: LoadedPolicy,
  ids: IdFactory = defaultIds,
  actor: TransactionActor = { credential: 'proc:authz', claimed_role: null },
): Promise<SweepResult> {
  const completed = await store.transactWithState('sweep', actor, (state, at) => {
    const ops: WalOp[] = [];
    const terminalRulings = new Set<string>();
    const releasedReservations = new Set<string>();
    const newPatternEvents: PatternEvent[] = [];
    let expiredRulings = 0;
    let timedOutEscalations = 0;
    let expiredMandates = 0;
    let narrowedMandates = 0;

    const releaseRulingReservations = (ruling: GateRuling, reason: string): void => {
      for (const reservation of ruling.counter_reservations) {
        if (
          !releasedReservations.has(reservation.id) &&
          state.reservations.get(reservation.id)?.state === 'reserved'
        ) {
          ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason });
          releasedReservations.add(reservation.id);
        }
      }
    };
    const endIssuedRuling = (ruling: GateRuling, reason: string, expired: boolean): void => {
      if (ruling.status !== 'issued' || terminalRulings.has(ruling.ruling_id)) return;
      ops.push(
        expired
          ? { op: 'ruling.expire', ruling_id: ruling.ruling_id }
          : { op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason },
      );
      terminalRulings.add(ruling.ruling_id);
      releaseRulingReservations(ruling, reason);
      const nonce = state.nonces.get(ruling.binding.nonce);
      if (expired && nonce?.state === 'issued') ops.push({ op: 'nonce.expire', nonce_id: nonce.nonce_id });
    };

    for (const ruling of state.rulings.values()) {
      if (ruling.status === 'issued' && at >= ruling.binding.validity_window.not_after) {
        endIssuedRuling(ruling, 'ruling-expiry', true);
        expiredRulings += 1;
      }
    }

    for (const escalation of state.escalations.values()) {
      if (escalation.state !== 'open' || at < escalation.expires_at) continue;
      const appliedDefault = escalation.contract.response_bound_and_default.safe_default.disposition;
      ops.push({ op: 'escalation.timeout', escalation_id: escalation.escalation_id, applied_default: appliedDefault });
      const ruling = state.rulings.get(escalation.ruling_id);
      if (ruling === undefined) throw new Error(`escalation ${escalation.escalation_id} lost its ruling`);
      endIssuedRuling(ruling, 'escalation-timeout', at >= ruling.binding.validity_window.not_after);
      const pattern: PatternEvent = {
        world_id: state.worldId,
        event_id: ids.next('pat'),
        mandate_id: ruling.binding.mandate_id,
        escalation_id: escalation.escalation_id,
        kind: 'timeout',
        at,
      };
      newPatternEvents.push(pattern);
      ops.push({ op: 'pattern.record', event: pattern });
      ops.push({
        op: 'record.action.append',
        entry: timeoutRecord(
          state,
          ruling,
          escalation.escalation_id,
          appliedDefault,
          ids.next('rec'),
          at,
        ),
      });
      timedOutEscalations += 1;
    }

    const expiringMandates = new Set<string>();
    for (const [mandateId, status] of state.mandateStatus) {
      if (status.state === 'revoked' || status.state === 'expired') continue;
      const current = state.mandates.get(mandateVersionKey(mandateId, status.version));
      if (current === undefined || at < current.expires_at) continue;
      expiringMandates.add(mandateId);
      for (const ruling of state.rulings.values()) {
        if (ruling.binding.mandate_id === mandateId) endIssuedRuling(ruling, 'mandate-expiry', true);
      }
      ops.push({ op: 'mandate.expire', mandate_id: mandateId, version: status.version, expired_at: at });
      expiredMandates += 1;
    }

    const affectedMandates = new Set(newPatternEvents.map((event) => event.mandate_id));
    for (const mandateId of affectedMandates) {
      const status = state.mandateStatus.get(mandateId);
      const current = status === undefined ? undefined : state.mandates.get(mandateVersionKey(mandateId, status.version));
      if (current === undefined || current.state !== 'active' || expiringMandates.has(mandateId)) continue;
      if (
        !escalationPatternRequiresNarrowing(
          policy.policy,
          [...state.patternEvents, ...newPatternEvents],
          mandateId,
          at,
        )
      ) {
        continue;
      }
      for (const ruling of state.rulings.values()) {
        if (ruling.binding.mandate_id === mandateId) {
          endIssuedRuling(ruling, 'escalation-pattern-narrowing', false);
        }
      }
      ops.push({
        op: 'mandate.amend',
        mandate: bindMandate(keyring, {
          ...mandateBody(current),
          version: current.version + 1,
          state: 'suspended',
          issued_at: at,
        }),
      });
      narrowedMandates += 1;
    }

    return {
      ops,
      result: {
        changed: ops.length > 0,
        expiredRulings,
        timedOutEscalations,
        expiredMandates,
        narrowedMandates,
      },
    };
  });
  return completed.result;
}
