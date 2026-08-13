// SPDX-License-Identifier: AGPL-3.0-only
/** Replay-complete write-ahead-log contracts — ADR-001 §§2, 9. */
import { z } from 'zod';

import { credentialLabel, hexDigest, id, integer, modelId, role, timestamp, worldId } from './common.js';
import { disposition } from './intervention.js';
import { mandate } from './mandate.js';
import { frozenProposal } from './proposal.js';
import {
  proposalIntakeRecord,
  proposalIntakeRefusalReason,
  proposalOriginRecord,
} from './proposalIntake.js';
import {
  proposalRevisionInvalidationReason,
  proposalRevisionPreparationRecord,
} from './proposalRevision.js';
import { accessChainEntry, recordEntry } from './record.js';
import { gateRuling } from './ruling.js';
import { modelCallFailureReason, modelCallOpenRecord, modelCallReportableFailureReason } from './modelCall.js';
import { liveScreeningSignal, screeningCallOpenRecord } from './screeningCall.js';
import {
  modelSelectionCheckRecord,
  modelSelectionObservation,
  modelSelectionTransition,
} from './modelSelection.js';
import {
  caseSessionHandoffRecord,
  commitmentRecord,
  effectRecord,
  escalationRecord,
  nonceRecord,
  patternEvent,
  policyActivation,
  reservationRecord,
  reviewObligation,
} from './state.js';
import { conversationStoreEntry } from './store.js';
import {
  caseSessionProvenanceReceipt,
  conversationIngressEvent,
  outputReleaseConsumptionResult,
  outputReleaseRecord,
} from './conversationTransport.js';
import { systemUseDecisionRecord, systemUseDecisionStatus } from './systemUseDecision.js';

const transitionReason = z.string().min(1);

export const walOp = z.discriminatedUnion('op', [
  z.object({ op: z.literal('proposal_revision_preparation.issue'), preparation: proposalRevisionPreparationRecord }).strict(),
  z
    .object({
      op: z.literal('proposal_revision_preparation.consume'),
      preparation_id: id,
      call_id: id,
      changed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('proposal_revision_preparation.invalidate'),
      preparation_id: id,
      reason: proposalRevisionInvalidationReason,
      changed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('proposal_revision_preparation.expire'),
      preparation_id: id,
      authorization_boot_id: id,
      changed_at: timestamp,
    })
    .strict(),
  z.object({ op: z.literal('proposal.freeze'), proposal: frozenProposal }).strict(),
  z.object({ op: z.literal('proposal_origin.put'), origin: proposalOriginRecord }).strict(),
  z.object({ op: z.literal('proposal_intake.issue'), intake: proposalIntakeRecord }).strict(),
  z
    .object({
      op: z.literal('proposal_intake.consume'),
      proposal_intake_id: id,
      proposal_id: id,
      changed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('proposal_intake.refuse'),
      proposal_intake_id: id,
      reason: proposalIntakeRefusalReason,
      changed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('proposal_intake.invalidate'),
      proposal_intake_id: id,
      reason: proposalIntakeRefusalReason,
      changed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('proposal_intake.expire'),
      proposal_intake_id: id,
      authorization_boot_id: id,
      changed_at: timestamp,
    })
    .strict(),

  z.object({ op: z.literal('system_use_decision.issue'), decision: systemUseDecisionRecord }).strict(),
  z
    .object({
      op: z.literal('system_use_decision.transition'),
      decision_id: id,
      version: integer.min(1),
      status: systemUseDecisionStatus,
      changed_at: timestamp,
    })
    .strict(),

  z.object({ op: z.literal('case_session_handoff.issue'), handoff: caseSessionHandoffRecord }).strict(),
  z.object({ op: z.literal('case_session_handoff.consume'), handoff_id: id, consumed_at: timestamp }).strict(),
  z.object({ op: z.literal('case_session_handoff.expire'), handoff_id: id }).strict(),
  z.object({ op: z.literal('case_session_provenance.issue'), receipt: caseSessionProvenanceReceipt }).strict(),
  z.object({ op: z.literal('case_session_provenance.expire'), session_id: id }).strict(),
  z.object({ op: z.literal('case_session_provenance.close'), session_id: id, closed_at: timestamp }).strict(),

  z.object({ op: z.literal('nonce.issue'), nonce: nonceRecord }).strict(),
  z.object({ op: z.literal('nonce.consume'), nonce_id: id }).strict(),
  z.object({ op: z.literal('nonce.expire'), nonce_id: id }).strict(),

  z.object({ op: z.literal('reservation.reserve'), reservation: reservationRecord }).strict(),
  z.object({ op: z.literal('reservation.settle'), reservation_id: id }).strict(),
  z.object({ op: z.literal('reservation.release'), reservation_id: id, reason: transitionReason }).strict(),
  z.object({ op: z.literal('reservation.hold_for_reconciliation'), reservation_id: id }).strict(),
  z
    .object({
      op: z.literal('reservation.reconcile'),
      reservation_id: id,
      resolution: z.enum(['settled', 'released']),
    })
    .strict(),

  z.object({ op: z.literal('ruling.issue'), ruling: gateRuling }).strict(),
  z.object({ op: z.literal('ruling.consume'), ruling_id: id }).strict(),
  z.object({ op: z.literal('ruling.invalidate'), ruling_id: id, reason: transitionReason }).strict(),
  z.object({ op: z.literal('ruling.expire'), ruling_id: id }).strict(),
  z.object({ op: z.literal('ruling.link_successor'), ruling_id: id, successor_ruling_id: id }).strict(),

  z.object({ op: z.literal('commitment.bind'), commitment: commitmentRecord }).strict(),
  z
    .object({
      op: z.literal('commitment.discharge'),
      commitment_id: id,
      outcome: z.enum(['success', 'failed']),
    })
    .strict(),
  z
    .object({
      op: z.literal('commitment.mark_unknown'),
      commitment_id: id,
      recovery_owner_role: role,
    })
    .strict(),
  z
    .object({
      op: z.literal('commitment.reconcile'),
      commitment_id: id,
      resolution: z.enum(['success', 'failed', 'no-effect', 'routed']),
    })
    .strict(),

  z.object({ op: z.literal('escalation.open'), escalation: escalationRecord }).strict(),
  z.object({ op: z.literal('escalation.dispose'), escalation_id: id, disposition }).strict(),
  z.object({ op: z.literal('escalation.link_successor'), escalation_id: id, successor_ruling_id: id }).strict(),
  z.object({ op: z.literal('escalation.timeout'), escalation_id: id, applied_default: disposition }).strict(),
  z.object({ op: z.literal('escalation.cancel'), escalation_id: id }).strict(),

  z.object({ op: z.literal('effect.record'), effect: effectRecord }).strict(),

  z.object({ op: z.literal('mandate.grant'), mandate }).strict(),
  z.object({ op: z.literal('mandate.amend'), mandate }).strict(),
  z
    .object({
      op: z.literal('mandate.revoke'),
      mandate_id: id,
      version: integer.min(1),
      revoked_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('mandate.expire'),
      mandate_id: id,
      version: integer.min(1),
      expired_at: timestamp,
    })
    .strict(),
  z.object({ op: z.literal('policy.reload'), policy: policyActivation }).strict(),

  z.object({ op: z.literal('store.put'), entry: conversationStoreEntry }).strict(),
  z.object({ op: z.literal('store.remove'), case_id: id, item_id: id, reason: transitionReason }).strict(),
  z.object({ op: z.literal('conversation.event.append'), event: conversationIngressEvent }).strict(),
  z.object({ op: z.literal('pattern.record'), event: patternEvent }).strict(),
  z.object({ op: z.literal('model_selection_check.issue'), check: modelSelectionCheckRecord }).strict(),
  z
    .object({ op: z.literal('model_selection_check.consume'), check_id: id, consumed_at: timestamp })
    .strict(),
  z.object({ op: z.literal('model_selection_check.expire'), check_id: id }).strict(),
  z.object({ op: z.literal('model_selection.append'), selection: modelSelectionTransition }).strict(),
  z.object({ op: z.literal('model_selection.observe'), observation: modelSelectionObservation }).strict(),
  z.object({ op: z.literal('model_call.open'), call: modelCallOpenRecord }).strict(),
  z
    .object({
      op: z.literal('model_call.complete'),
      call_id: id,
      outcome: z.enum(['admitted', 'withheld']),
      served_id: modelId,
      output_digest: hexDigest,
      completed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('model_call.fail'),
      call_id: id,
      provider_disclosure: z.enum(['possible', 'confirmed']),
      served_id: modelId.nullable(),
      failure_reason: modelCallFailureReason,
      completed_at: timestamp,
    })
    .strict(),
  z.object({ op: z.literal('screening_call.open'), call: screeningCallOpenRecord }).strict(),
  z
    .object({
      op: z.literal('screening_call.complete'),
      call_id: id,
      served_id: modelId,
      model_resolution: z.enum(['exact', 'benign-resolution']),
      output_digest: hexDigest,
      signals: z.array(liveScreeningSignal).max(16),
      completed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('screening_call.fail'),
      call_id: id,
      provider_disclosure: z.enum(['possible', 'confirmed']),
      served_id: modelId.nullable(),
      model_resolution: z.enum(['exact', 'benign-resolution', 'mismatch']).nullable(),
      output_digest: hexDigest.nullable(),
      failure_reason: modelCallReportableFailureReason,
      completed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('screening_call.invalidate'),
      call_id: id,
      failure_reason: z.enum(['authorization-invalidated', 'system-use-invalidated']),
      completed_at: timestamp,
    })
    .strict(),
  z.object({ op: z.literal('output_release.issue'), release: outputReleaseRecord }).strict(),
  z
    .object({
      op: z.literal('output_release.consume'),
      release_id: id,
      result: outputReleaseConsumptionResult,
    })
    .strict(),
  z
    .object({
      op: z.literal('output_release.invalidate'),
      release_id: id,
      reason: transitionReason,
      changed_at: timestamp,
    })
    .strict(),
  z
    .object({
      op: z.literal('output_release.expire'),
      release_id: id,
      authorization_boot_id: id,
      changed_at: timestamp,
    })
    .strict(),
  z.object({ op: z.literal('review.open'), obligation: reviewObligation }).strict(),
  z
    .object({
      op: z.literal('review.resolve'),
      obligation_id: id,
      resolution: z.enum(['resolved', 'cancelled']),
      resolved_at: timestamp,
    })
    .strict(),

  z.object({ op: z.literal('record.action.append'), entry: recordEntry }).strict(),
  z.object({ op: z.literal('record.access.append'), entry: accessChainEntry }).strict(),
]);

export type WalOp = z.infer<typeof walOp>;

export const walGenesisHeader = z
  .object({
    kind: z.literal('genesis'),
    wal_version: z.literal(3),
    world_id: worldId,
    created_at: timestamp,
  })
  .strict();

export const walRunHeader = z
  .object({
    kind: z.literal('run'),
    world_id: worldId,
    ts: timestamp,
    run_id: id,
    boot_id: id,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_digest: hexDigest,
  })
  .strict();

export const walTransaction = z
  .object({
    kind: z.literal('transaction'),
    world_id: worldId,
    ts: timestamp,
    txn: z.string().regex(/^[a-z][a-z0-9_]*$/, 'expected a lowercase transaction name'),
    run_id: id,
    actor: z
      .object({
        credential: credentialLabel,
        claimed_role: role.nullable(),
      })
      .strict(),
    ops: z.array(walOp).min(1),
  })
  .strict();

export type WalTransaction = z.infer<typeof walTransaction>;

export const walLine = z.discriminatedUnion('kind', [walGenesisHeader, walRunHeader, walTransaction]);
export type WalLine = z.infer<typeof walLine>;
