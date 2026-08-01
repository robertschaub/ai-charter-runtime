// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Gate ruling — spec §4, ADR-001 §4 (binding tuple and invalidation), ADR-005 §5
 * (projection summaries ride in the evidence refs, no new record fields).
 */
import { z } from 'zod';

import {
  cardSlug,
  classToken,
  confidencePct,
  hexDigest,
  id,
  integer,
  minorUnits,
  modelId,
  modelRole,
  restrictionTagSet,
  timestamp,
  validityWindow,
  worldId,
} from './common.js';

/** The five runtime gates. */
export const GATES = ['authorize', 'submit', 'verify', 'commit', 'rely'] as const;
export const gate = z.enum(GATES);

export const VERDICTS = ['allow', 'deny', 'escalate'] as const;
export const verdict = z.enum(VERDICTS);

export const UX_CLASSES = ['silent', 'flag', 'stop'] as const;
export const uxClass = z.enum(UX_CLASSES);

/** ADR-001 §3: `issued -> consumed | invalidated | expired`. */
export const RULING_STATUSES = ['issued', 'consumed', 'invalidated', 'expired'] as const;
export const rulingStatus = z.enum(RULING_STATUSES);

/** Spec §4: a signal can trigger Flag or Escalate; no code path leads from one to allow. */
export const SCREENING_SIGNALS = [
  'injection_suspicion',
  'evidence_conflict',
  'unconfirmed_inference_as_fact',
  'scope_drift',
] as const;

export const screeningSignal = z.object({
  kind: z.literal('screening_signal'),
  signal: z.enum(SCREENING_SIGNALS),
  confidence_pct: confidencePct,
  rationale: z.string(),
  /** Model id and version as reported by the serving API. */
  model_id: modelId,
  model_version_reported: modelId,
});

/** ADR-005 §5: every projection records a summary in the ruling's evidence refs. */
export const submitProjectionRef = z.object({
  kind: z.literal('submit_projection'),
  provider: cardSlug,
  role: modelRole,
  included: integer.min(0),
  dropped: integer.min(0),
  dropped_item_ids: z.array(id),
  unmet_tags: restrictionTagSet,
});

/** ADR-004 §4: the cited evidence behind a `confirm` on a third-party fact. */
export const registryRecordRef = z.object({
  kind: z.literal('registry_record'),
  id: z.string().min(1),
  retrieved_at: timestamp,
});

export const humanInterventionRef = z.object({
  kind: z.literal('human_intervention_event'),
  escalation_id: id,
  record_entry_id: id,
});

export const recordEntryRef = z.object({
  kind: z.literal('record_entry'),
  entry_id: id,
});

export const evidenceRef = z.discriminatedUnion('kind', [
  screeningSignal,
  submitProjectionRef,
  registryRecordRef,
  humanInterventionRef,
  recordEntryRef,
]);

export type EvidenceRef = z.infer<typeof evidenceRef>;

/**
 * ADR-001 §4's binding tuple. The policy version and policy content digest belong to the
 * tuple too, but are recorded once at ruling level (spec §4) rather than duplicated here —
 * a hashed artifact should not carry the same fact twice.
 */
export const rulingBinding = z.object({
  frozen_proposal_hash: hexDigest,
  mandate_id: id,
  mandate_version: integer.min(1),
  acting_model_id: modelId,
  /** ADR-006: the card digest and the key id that verified it, behind the model entry. */
  card_digest: hexDigest,
  card_key_id: id,
  service: id,
  action_class: classToken,
  /** Issued with the ruling, consumed exactly once at `commit-verify`. */
  nonce: id,
  validity_window: validityWindow,
});

/** ADR-001 §5: positive deltas count from reservation, negative only from settlement. */
export const COUNTERS = ['actions', 'amount', 'notification_volume', 'escalation_pattern'] as const;
export const counterName = z.enum(COUNTERS);

export const counterReservation = z.object({
  id,
  counter: counterName,
  delta: minorUnits,
});

export const gateRuling = z.object({
  world_id: worldId,
  ruling_id: id,
  gate,
  verdict,
  /** Null when no rule matched and the default-escalate rule fired (spec §4). */
  matched_rule_id: id.nullable(),

  /** A version label alone cannot prove which rules ran, so all three are recorded. */
  policy_version: z.string().min(1),
  policy_content_digest: hexDigest,
  evaluator_build_id: z.string().min(1),

  binding: rulingBinding,

  ux_class: uxClass,
  reason: z.string().min(1),
  evidence_refs: z.array(evidenceRef),
  /** Absent on a verdict that reserves nothing. */
  counter_reservation: counterReservation.nullable(),

  issued_at: timestamp,
  status: rulingStatus,
  /** Set when an "allow within scope" disposition mints a successor (ADR-002 §5). */
  successor_ruling_id: id.nullable().optional(),
});

export type GateRuling = z.infer<typeof gateRuling>;
