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
import { modelCallAccessEvidence } from './modelCall.js';
import { modelSelectionAccessEvidence } from './modelSelection.js';
import { conversationTransportAccessEvidence } from './conversationTransport.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

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
  system_use_decision: systemUseDecisionReference,
  system_use_current_at_record: z.literal(true),
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
  system_use_decision: systemUseDecisionReference,
  system_use_current_at_record: z.boolean(),
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
      kind: z.literal('disposition_refused'),
      attempted_disposition: disposition,
      authenticated_actor: credentialLabel,
      reason_code: z.enum(['wrong_role', 'disposition_not_permitted']),
      at: timestamp,
    }).strict(),
    z.object({
      kind: z.literal('revision_continuation_refused'),
      proposal_id: id,
      authenticated_actor: credentialLabel,
      reason_code: z.enum(['wrong_state', 'revision_not_permitted', 'already_continued']),
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
      /** Machine binding for every disposition that changes conversation state. */
      scope: z
        .object({ item_ref: id, applies_to: z.literal('this_case_only') })
        .strict()
        .nullable()
        .optional(),
    }).strict(),
    z.object({
      kind: z.literal('dialogue_response_refused'),
      reason_code: z.enum(['evidence_required', 'wrong_role', 'disposition_not_permitted', 'invalid_response']),
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

export const challengeAndRemedy = z
  .object({
    route: z.string(),
    opened_at: timestamp,
    contested_entry_id: id.optional(),
    correction_text: z.string().min(1).max(32_768).optional(),
    reliance_state: z.literal('withdrawn-pending-review').optional(),
    recovery_owner_role: role.optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const challengeFields = ['contested_entry_id', 'correction_text', 'reliance_state', 'recovery_owner_role'] as const;
    if (value.route !== 'challenge') {
      for (const field of challengeFields) {
        if (value[field] !== undefined) {
          context.addIssue({ code: 'custom', path: [field], message: `${field} is challenge-only` });
        }
      }
      return;
    }
    for (const field of challengeFields) {
      if (value[field] === undefined) {
        context.addIssue({ code: 'custom', path: [field], message: `challenge requires ${field}` });
      }
    }
  });

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
  /** Null only for a terminal denial made before a usable mandate exists. */
  system_use_decision: systemUseDecisionReference.nullable(),
  system_use_current_at_record: z.boolean(),

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
  challenge_and_remedy: challengeAndRemedy.nullable(),
})
  .strict()
  .superRefine((entry, context) => {
    if (entry.admissibility_decision.verdict !== 'deny' && entry.system_use_decision === null) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['system_use_decision'],
        message: 'an allow or escalate record requires a current system-use decision reference',
      });
    }
    if (entry.system_use_decision === null && entry.system_use_current_at_record) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['system_use_current_at_record'],
        message: 'a missing decision reference cannot be current',
      });
    }
    if (
      entry.commitment_and_effect !== null &&
      'system_use_decision' in entry.commitment_and_effect &&
      entry.system_use_decision !== null &&
      JSON.stringify(entry.commitment_and_effect.system_use_decision) !== JSON.stringify(entry.system_use_decision)
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['commitment_and_effect', 'system_use_decision'],
        message: 'commitment/effect decision reference must match the record reference',
      });
    }
  });

export type RecordEntry = z.infer<typeof recordEntry>;

/** ADR-002 §7: the record family writes to the access-log chain before returning. */
export const accessEntry = z
  .object({
    world_id: worldId,
    entry_id: id,
    at: timestamp,
    route: z.string().min(1),
    /** Null when no bearer credential could be authenticated. */
    authenticated_actor: credentialLabel.nullable(),
    claimed_actor: claimedActor.nullable(),
    outcome: z.enum(['served', 'unauthenticated', 'forbidden', 'rate-limited']),
    http_status: integer.min(100).max(599),
    /** Lower-bound marker or final count for a bounded unauthenticated suppression window. */
    suppressed_count: integer.min(1).optional(),
    suppression_window_ms: integer.min(1).optional(),
    suppression_final: z.boolean().optional(),
    /** ADR-003 step 6: verification records the lengths it read. */
    read_lengths: z.record(z.string(), integer.min(0)).optional(),
    /** Bounded lifecycle/selection/transport metadata; raw provider material never enters the access chain. */
    operation_evidence: z
      .union([modelCallAccessEvidence, modelSelectionAccessEvidence, conversationTransportAccessEvidence])
      .optional(),
  })
  .strict()
  .superRefine((entry, ctx) => {
    const suppressionFields = [entry.suppressed_count, entry.suppression_window_ms, entry.suppression_final];
    if (entry.outcome === 'rate-limited') {
      if (suppressionFields.some((value) => value === undefined)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['suppressed_count'],
          message: 'rate-limited entries require the complete suppression-window summary',
        });
      }
      if (entry.authenticated_actor !== null || entry.http_status !== 429) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['outcome'],
          message: 'rate-limited entries are unauthenticated 429 evidence',
        });
      }
    } else if (suppressionFields.some((value) => value !== undefined)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['suppressed_count'],
        message: 'suppression-window fields are only valid on rate-limited entries',
      });
    }
    if (entry.operation_evidence !== undefined) {
      const evidence = entry.operation_evidence;
      const expectedRoute =
        evidence.kind === 'conversation_message_ingress'
          ? 'POST /w/{world_id}/cases/{case_id}/conversation/messages'
          : evidence.kind === 'output_release_consumed'
            ? 'POST /w/{world_id}/model-output-releases/{id}/consume'
            : evidence.kind === 'output_release_status'
              ? 'GET /w/{world_id}/model-output-releases/{id}'
              : evidence.kind === 'conversation_read'
                ? 'GET /w/{world_id}/cases/{case_id}/conversation'
                : evidence.kind === 'model_selection_read'
          ? 'GET /w/{world_id}/cases/{case_id}/model-selection'
          : evidence.kind === 'model_selection_check'
            ? 'POST /w/{world_id}/cases/{case_id}/model-selection-checks'
            : evidence.kind === 'model_selection_result'
              ? 'POST /w/{world_id}/cases/{case_id}/model-selections'
              : evidence.kind === 'model_call_admission'
                ? 'POST /w/{world_id}/model-outputs/admit'
                  : evidence.outcome === 'indeterminate'
                    ? 'POST /w/{world_id}/model-calls/begin'
                    : 'POST /w/{world_id}/model-calls/failures';
      if (
        entry.route !== expectedRoute ||
        entry.authenticated_actor !== 'proc:orchestrator' ||
        entry.outcome !== 'served' ||
        entry.http_status !== 200
      ) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['operation_evidence'],
          message: 'operation evidence is valid only on its served orchestrator lifecycle route',
        });
      }
    }
  });

export const accessChainEntry = z.union([accessEntry, anchorEvent, anchorFailedEvent]);

export type AccessEntry = z.infer<typeof accessEntry>;
