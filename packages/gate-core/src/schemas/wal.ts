// SPDX-License-Identifier: AGPL-3.0-only
/** Replay-complete write-ahead-log contracts — ADR-001 §§2, 9. */
import { z } from 'zod';

import { credentialLabel, hexDigest, id, integer, role, timestamp, worldId } from './common.js';
import { disposition } from './intervention.js';
import { mandate } from './mandate.js';
import { frozenProposal } from './proposal.js';
import { accessChainEntry, recordEntry } from './record.js';
import { gateRuling } from './ruling.js';
import {
  commitmentRecord,
  effectRecord,
  escalationRecord,
  modelSelectionRecord,
  nonceRecord,
  patternEvent,
  policyActivation,
  reservationRecord,
  reviewObligation,
} from './state.js';
import { storeItem } from './store.js';

const transitionReason = z.string().min(1);

export const walOp = z.discriminatedUnion('op', [
  z.object({ op: z.literal('proposal.freeze'), proposal: frozenProposal }).strict(),

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
      resolution: z.enum(['success', 'failed', 'routed']),
    })
    .strict(),

  z.object({ op: z.literal('escalation.open'), escalation: escalationRecord }).strict(),
  z.object({ op: z.literal('escalation.dispose'), escalation_id: id, disposition }).strict(),
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

  z.object({ op: z.literal('store.put'), item: storeItem }).strict(),
  z.object({ op: z.literal('store.remove'), item_id: id, reason: transitionReason }).strict(),
  z.object({ op: z.literal('pattern.record'), event: patternEvent }).strict(),
  z.object({ op: z.literal('model.select'), selection: modelSelectionRecord }).strict(),
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
    wal_version: z.literal(2),
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
