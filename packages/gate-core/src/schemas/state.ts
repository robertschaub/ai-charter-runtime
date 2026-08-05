// SPDX-License-Identifier: AGPL-3.0-only
/** Replay-complete transactional state artifacts. */
import { z } from 'zod';

import { classToken, hexDigest, id, integer, role, timestamp, worldId } from './common.js';
import { disposition, interventionContract } from './intervention.js';
import { counterName, gateRuling } from './ruling.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

export const browserOrigin = z
  .string()
  .url()
  .refine((value) => {
    const parsed = new URL(value);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.origin === value;
  }, 'expected an exact HTTP(S) origin');

export const CASE_SESSION_HANDOFF_STATES = ['issued', 'consumed', 'expired'] as const;
export const caseSessionHandoffState = z.enum(CASE_SESSION_HANDOFF_STATES);
export const caseSessionHandoffRecord = z
  .object({
    world_id: worldId,
    handoff_id: id,
    case_id: id,
    role: z.literal('case_officer'),
    target_origin: browserOrigin,
    authorization_boot_id: id,
    code_digest: hexDigest,
    created_at: timestamp,
    expires_at: timestamp,
    consumed_at: timestamp.nullable(),
    state: caseSessionHandoffState,
  })
  .strict()
  .superRefine((record, ctx) => {
    if (record.created_at > record.expires_at) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'handoff expires before creation' });
    }
    if ((record.state === 'consumed') !== (record.consumed_at !== null)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['consumed_at'],
        message: 'only a consumed handoff carries a consumption timestamp',
      });
    }
  });
export type CaseSessionHandoffRecord = z.infer<typeof caseSessionHandoffRecord>;

export const NONCE_STATES = ['issued', 'consumed', 'expired'] as const;
export const nonceState = z.enum(NONCE_STATES);
export const nonceRecord = z
  .object({
    world_id: worldId,
    nonce_id: id,
    ruling_id: id,
    expires_at: timestamp,
    state: nonceState,
  })
  .strict();
export type NonceRecord = z.infer<typeof nonceRecord>;

export const RESERVATION_STATES = [
  'reserved',
  'settled',
  'held_for_reconciliation',
  'released',
] as const;
export const reservationState = z.enum(RESERVATION_STATES);
export const reservationRecord = z
  .object({
    world_id: worldId,
    reservation_id: id,
    ruling_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    counter: counterName,
    delta: integer,
    reserved_at: timestamp,
    expires_at: timestamp,
    state_changed_at: timestamp,
    state: reservationState,
  })
  .strict()
  .superRefine((record, ctx) => {
    if (record.reserved_at > record.expires_at) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['expires_at'], message: 'reservation expires before issue' });
    }
    if (record.state === 'reserved' && record.state_changed_at !== record.reserved_at) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['state_changed_at'],
        message: 'a fresh reservation changes state when it is reserved',
      });
    }
  });
export type ReservationRecord = z.infer<typeof reservationRecord>;

export const COMMITMENT_STATES = ['bound', 'discharged', 'unknown', 'reconciled'] as const;
export const commitmentState = z.enum(COMMITMENT_STATES);
export const commitmentRecord = z
  .object({
    world_id: worldId,
    commitment_id: id,
    ruling_id: id,
    frozen_proposal_hash: hexDigest,
    effect_id: id,
    effect_request_digest: hexDigest,
    idempotency_key: hexDigest,
    service: id,
    action_class: classToken,
    bound_at: timestamp,
    token_expires_at: timestamp,
    services_host_boot_id: id,
    services_ledger_id: id,
    system_use_decision: systemUseDecisionReference,
    system_use_current_at_bind: z.literal(true),
    /** Pinned at commitment time so a later policy reload cannot reroute recovery. */
    recovery_contract: interventionContract,
    state: commitmentState,
    outcome: z.enum(['success', 'failed', 'no-effect', 'unknown-reconciliation-required']).nullable(),
    recovery_owner_role: role,
  })
  .strict()
  .superRefine((record, ctx) => {
    if (record.recovery_contract.decision_and_route.eligible_role !== record.recovery_owner_role) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['recovery_owner_role'],
        message: 'recovery owner must be the pinned recovery contract eligible role',
      });
    }
  });
export type CommitmentRecord = z.infer<typeof commitmentRecord>;

export const ESCALATION_STATES = ['open', 'disposed', 'timed_out', 'cancelled'] as const;
export const escalationState = z.enum(ESCALATION_STATES);
export const escalationRecord = z
  .object({
    world_id: worldId,
    escalation_id: id,
    /** Required on dialogue escalations so a response cannot update another case. */
    case_id: id.nullable().default(null),
    ruling_id: id,
    /** Null for a ruling escalation; set when an unknown commitment opens recovery. */
    source_commitment_id: id.nullable().default(null),
    frozen_proposal_hash: hexDigest,
    contract: interventionContract,
    opened_at: timestamp,
    expires_at: timestamp,
    state: escalationState,
    terminal_disposition: disposition.nullable(),
    successor_ruling_id: id.nullable(),
  })
  .strict();
export type EscalationRecord = z.infer<typeof escalationRecord>;

export const effectRecord = z
  .object({
    world_id: worldId,
    effect_id: id,
    commitment_id: id,
    idempotency_key: hexDigest,
    effect_request_digest: hexDigest,
    services_ledger_id: id,
    system_use_decision: systemUseDecisionReference,
    system_use_current_at_record: z.boolean(),
    outcome: z.enum(['success', 'failed', 'unknown-reconciliation-required']),
    recorded_at: timestamp,
    detail: z.string().optional(),
  })
  .strict();
export type EffectRecord = z.infer<typeof effectRecord>;

export const policyActivation = z
  .object({
    world_id: worldId,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    activated_at: timestamp,
  })
  .strict();
export type PolicyActivation = z.infer<typeof policyActivation>;

export const PATTERN_EVENTS = ['escalation', 'timeout', 'override'] as const;
export const patternEvent = z
  .object({
    world_id: worldId,
    event_id: id,
    mandate_id: id,
    escalation_id: id,
    kind: z.enum(PATTERN_EVENTS),
    at: timestamp,
  })
  .strict();
export type PatternEvent = z.infer<typeof patternEvent>;

export const REVIEW_STATES = ['open', 'resolved', 'cancelled'] as const;
export const reviewObligation = z
  .object({
    world_id: worldId,
    obligation_id: id,
    case_id: id,
    source_entry_id: id,
    route: z.string().min(1),
    recovery_owner_role: role,
    opened_at: timestamp,
    state: z.enum(REVIEW_STATES),
    resolved_at: timestamp.nullable(),
  })
  .strict();
export type ReviewObligation = z.infer<typeof reviewObligation>;

/** Stored copy used to connect a ruling id to its complete immutable ruling. */
export const issuedRulingRecord = gateRuling;
