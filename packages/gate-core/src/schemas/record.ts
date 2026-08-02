// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Record entry and record events — spec §4 (the split-custody field list), ADR-001 §6-§7
 * (`retry_served`, `late_disposition_ignored`), ADR-003 (anchor events on the access-log
 * chain), ADR-004 §8 (the dialogue events, carried on the existing record fields — no new
 * governance-semantic fields).
 *
 * `commitment_and_effect` is populated by two events: a pre-effect `commitment` sealed
 * before the effect executes, and a post-effect `effect_outcome`. Two events keep the
 * criterion-7 join truthful under crashes.
 */
import { z } from 'zod';

import {
  claimedActor,
  credentialLabel,
  hexDigest,
  id,
  integer,
  role,
  timestamp,
  worldId,
} from './common.js';
import { disposition, interventionContract, standingClass } from './intervention.js';

export const EFFECT_OUTCOMES = ['success', 'failed', 'no-effect', 'unknown-reconciliation-required'] as const;
export const effectOutcomeValue = z.enum(EFFECT_OUTCOMES);

/** Sealed before the effect executes (ADR-001 §6). */
export const commitmentEvent = z.object({
  event: z.literal('commitment'),
  commitment_id: id,
  ruling_id: id,
  effect_id: id,
  idempotency_key: hexDigest,
  frozen_proposal_hash: hexDigest,
  effect_request_digest: hexDigest,
  services_ledger_id: id,
  service: id,
  bound_at: timestamp,
  token_expires_at: timestamp,
}).strict();

export const effectOutcomeEvent = z.object({
  event: z.literal('effect_outcome'),
  effect_id: id,
  outcome: effectOutcomeValue,
  reported_at: timestamp,
  /** Criterion 7's named recovery owner, for the `unknown` case (ADR-001 §8). */
  recovery_owner_role: role.nullable(),
  detail: z.string().optional(),
}).strict();

/** ADR-001 §6: a retry with the same key returns the recorded outcome, never re-executes. */
export const retryServedEvent = z.object({
  event: z.literal('retry_served'),
  effect_id: id,
  idempotency_key: hexDigest,
  served_at: timestamp,
  recorded_outcome: z.enum(['success', 'failed']),
}).strict();

/** ADR-001 §7: every arrival after the first is a recorded no-op. */
export const lateDispositionIgnoredEvent = z.object({
  event: z.literal('late_disposition_ignored'),
  escalation_id: id,
  attempted_disposition: disposition,
  authenticated_actor: credentialLabel,
  terminal_state: z.enum(['disposed', 'timed_out', 'cancelled']),
  at: timestamp,
}).strict();

/** ADR-004 §8 — the four dialogue payloads, plus the general escalation events. */
export const humanInterventionEvent = z.object({
  event: z.literal('human_intervention_event'),
  escalation_id: id,
  payload: z.discriminatedUnion('kind', [
    z.object({
      kind: z.literal('escalation_raised'),
      contract: interventionContract,
      reason: z.string(),
    }).strict(),
    z.object({
      kind: z.literal('disposition_recorded'),
      disposition,
      responder_role: role,
      at: timestamp,
    }).strict(),
    z.object({
      kind: z.literal('dialogue_trigger_raised'),
      contract: interventionContract,
      standing_class: standingClass,
      question_text: z.string().min(1),
    }).strict(),
    z.object({
      kind: z.literal('dialogue_response_recorded'),
      disposition,
      responder_role: role,
      evidence_ref: z
        .object({
          kind: z.literal('registry_record'),
          id: z.string().min(1),
          retrieved_at: timestamp,
          resolved_at: timestamp,
          content_digest: hexDigest,
        })
        .strict()
        .nullable(),
      /** The answer text is testimony; only its digest rides in the event. */
      answer_digest: hexDigest.nullable(),
    }).strict(),
    z.object({
      kind: z.literal('dialogue_response_refused'),
      reason_code: z.enum(['evidence_required', 'wrong_role', 'disposition_not_permitted']),
      at: timestamp,
    }).strict(),
    z.object({
      kind: z.literal('dialogue_timeout'),
      applied_default: disposition,
      at: timestamp,
    }).strict(),
    z.object({
      kind: z.literal('escalation_timeout'),
      applied_default: disposition,
      at: timestamp,
    }).strict(),
  ]),
}).strict();

/** ADR-003: every anchor attempt appends one event to the access-log chain. */
export const anchorEvent = z.object({
  event: z.literal('anchor'),
  world_id: worldId,
  checkpoint_id: id,
  composite_digest: hexDigest,
  remote_sha: z.string().min(1),
  at: timestamp,
}).strict();

export const anchorFailedEvent = z.object({
  event: z.literal('anchor_failed'),
  world_id: worldId,
  checkpoint_id: id,
  error_class: z.string().min(1),
  at: timestamp,
}).strict();

export const recordEvent = z.discriminatedUnion('event', [
  commitmentEvent,
  effectOutcomeEvent,
  retryServedEvent,
  lateDispositionIgnoredEvent,
  humanInterventionEvent,
  anchorEvent,
  anchorFailedEvent,
]);

export type RecordEvent = z.infer<typeof recordEvent>;

export const commitmentAndEffectEvent = z.discriminatedUnion('event', [
  commitmentEvent,
  effectOutcomeEvent,
  retryServedEvent,
]);

export const interventionRecordEvent = z.discriminatedUnion('event', [
  humanInterventionEvent,
  lateDispositionIgnoredEvent,
]);

/**
 * The split-custody field list. `prev_hash` and `entry_hash` are assigned by the chain
 * writer (chain.ts), not by the caller, so they are not part of the authored payload.
 */
export const recordEntry = z.object({
  world_id: worldId,
  entry_id: id,
  at: timestamp,
  /** ADR-002 §4: two distinct fields; `claimed_actor` never decides authority. */
  authenticated_actor: credentialLabel,
  claimed_actor: claimedActor.nullable(),

  proposed_action: z.string(),
  basis: z.array(z.string()),
  authority_chain: z.array(id),
  admissibility_decision: z.object({
    ruling_id: id,
    verdict: z.enum(['allow', 'deny', 'escalate']),
  }).strict(),
  policy_model_version: z.object({
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    acting_model_requested_id: z.string().min(1),
    acting_model_served_id: z.string().min(1),
  }).strict(),
  commitment_and_effect: commitmentAndEffectEvent.nullable(),
  human_intervention_event: interventionRecordEvent.nullable(),
  challenge_and_remedy: z
    .object({
      route: z.string(),
      opened_at: timestamp,
    })
    .strict()
    .nullable(),
}).strict();

export type RecordEntry = z.infer<typeof recordEntry>;

/** ADR-002 §7: the record family writes to the access-log chain before returning. */
export const accessEntry = z.object({
  world_id: worldId,
  entry_id: id,
  at: timestamp,
  route: z.string().min(1),
  /** Null when no bearer credential could be authenticated. */
  authenticated_actor: credentialLabel.nullable(),
  claimed_actor: claimedActor.nullable(),
  outcome: z.enum(['served', 'unauthenticated', 'forbidden']),
  http_status: integer.min(100).max(599),
  /** ADR-003 step 6: verification records the lengths it read. */
  read_lengths: z.record(z.string(), integer.min(0)).optional(),
}).strict();

export const accessChainEntry = z.union([accessEntry, anchorEvent, anchorFailedEvent]);

export type AccessEntry = z.infer<typeof accessEntry>;
