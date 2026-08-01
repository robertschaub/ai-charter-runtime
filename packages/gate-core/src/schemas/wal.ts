// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Write-ahead log — ADR-001 §2.
 *
 * One append-only JSONL file per world. Line 0 is a genesis header; each process start
 * appends a run header; every other line is one **transaction**, so a whole action's
 * mutations land or none do.
 *
 * "Op vocabulary is closed and versioned. `apply(state, op)` is the *only* mutation path
 * in the service, which is what makes replay faithful by construction." The union below
 * is that closed vocabulary, derived from the §3 state machines, the §5 counters, the §7
 * disposition map, and the §8 sweeper. `seq`, `prev_hash` and `entry_hash` are assigned by
 * the chain writer, so they are not part of the authored transaction body.
 */
import { z } from 'zod';

import { classToken, credentialLabel, hexDigest, id, integer, minorUnits, role, timestamp, worldId } from './common.js';
import { counterName } from './ruling.js';
import { disposition } from './intervention.js';
import { recordEvent } from './record.js';

export const walOp = z.discriminatedUnion('op', [
  // nonce: issued -> consumed | expired
  z.object({ op: z.literal('nonce.issue'), id, expires_at: timestamp }),
  z.object({ op: z.literal('nonce.consume'), id }),
  z.object({ op: z.literal('nonce.expire'), id }),

  // reservation: reserved -> settled -> held_for_reconciliation -> settled | released
  z.object({ op: z.literal('reservation.reserve'), id, counter: counterName, delta: minorUnits }),
  z.object({ op: z.literal('reservation.settle'), id, counter: counterName, delta: minorUnits }),
  z.object({ op: z.literal('reservation.release'), id, reason: classToken }),
  z.object({ op: z.literal('reservation.hold_for_reconciliation'), id }),
  z.object({ op: z.literal('reservation.reconcile'), id, resolution: z.enum(['settled', 'released']) }),

  // ruling: issued -> consumed | invalidated | expired
  z.object({ op: z.literal('ruling.issue'), id, nonce: id }),
  z.object({ op: z.literal('ruling.consume'), id }),
  z.object({ op: z.literal('ruling.invalidate'), id, reason: classToken }),
  z.object({ op: z.literal('ruling.expire'), id }),

  // commitment: bound -> discharged | unknown -> reconciled
  z.object({
    op: z.literal('commitment.bind'),
    id,
    effect_id: id,
    idempotency_key: hexDigest,
    token_expires_at: timestamp,
  }),
  z.object({ op: z.literal('commitment.discharge'), id, outcome: z.enum(['success', 'failed']) }),
  z.object({ op: z.literal('commitment.mark_unknown'), id }),
  z.object({ op: z.literal('commitment.reconcile'), id, resolution: z.enum(['success', 'failed', 'routed']) }),

  // escalation: open -> disposed | timed_out | cancelled
  z.object({ op: z.literal('escalation.open'), id, eligible_role: role, response_bound_ms: integer.min(1) }),
  z.object({ op: z.literal('escalation.dispose'), id, disposition }),
  z.object({ op: z.literal('escalation.timeout'), id, applied_default: disposition }),
  z.object({ op: z.literal('escalation.cancel'), id }),

  // idempotency key: unused -> recorded (terminal)
  z.object({ op: z.literal('idempotency.record'), key: hexDigest, effect_id: id }),

  // mandate + policy changes, which drive ADR-001 §4's eager invalidation sweep
  z.object({ op: z.literal('mandate.grant'), id, version: integer.min(1) }),
  z.object({ op: z.literal('mandate.amend'), id, version: integer.min(1) }),
  z.object({ op: z.literal('mandate.revoke'), id }),
  z.object({ op: z.literal('policy.reload'), policy_version: z.string().min(1), policy_content_digest: hexDigest }),

  // record append (the action and access chains are materialized from these)
  z.object({
    op: z.literal('record.append'),
    chain: z.enum(['action', 'access']),
    entry_id: id,
    payload: recordEvent,
  }),
]);

export type WalOp = z.infer<typeof walOp>;

/** Line 0 of every WAL. */
export const walGenesisHeader = z.object({
  wal_version: integer.min(1),
  world_id: worldId,
  created_at: timestamp,
});

/** Appended at every process start (ADR-001 §2). */
export const walRunHeader = z.object({
  world_id: worldId,
  ts: timestamp,
  run_id: id,
  boot_id: id,
  policy_version: z.string().min(1),
  policy_content_digest: hexDigest,
  /** The full digest that ADR-007's short `evaluator_build_id` abbreviates. */
  evaluator_build_digest: hexDigest,
});

export const walTransaction = z.object({
  world_id: worldId,
  /** Non-decreasing; a backwards clock jump is rejected (ADR-001 §2 clock guard). */
  ts: timestamp,
  txn: z.string().regex(/^[a-z][a-z0-9_]*$/, 'expected a lowercase transaction name'),
  run_id: id,
  actor: z.object({
    credential: credentialLabel,
    claimed_role: role.nullable(),
  }),
  ops: z.array(walOp).min(1),
});

export type WalTransaction = z.infer<typeof walTransaction>;

/** Any line of a WAL file, before the chain writer adds `seq` / `prev_hash` / `entry_hash`. */
export const walLine = z.union([walTransaction, walRunHeader, walGenesisHeader]);

export type WalLine = z.infer<typeof walLine>;
