// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-002 fixed allowlist projections for data crossing into the model-side process. */
import { z } from 'zod';

import {
  accessChainEntry,
  approvedModelEntry,
  authorityHop,
  cardSlug,
  classToken,
  disposition,
  hexDigest,
  id,
  integer,
  interventionContract,
  mandateLimits,
  mandateState,
  modelCard,
  modelCallOpenRecord,
  modelRole,
  recordEntry,
  restrictionTagSet,
  role,
  rulingStatus,
  timestamp,
  uxClass,
  validityWindow,
  verdict,
  worldId,
  substitutionRules,
  storeItem,
} from './schemas/index.js';

export const rulingProjection = z
  .object({
    ruling_id: id,
    verdict,
    ux_class: uxClass,
    reason: z.string().min(1),
    status: rulingStatus,
    successor_ruling_id: id.nullable(),
    validity_window: validityWindow,
  })
  .strict();

export const proposalRulingProjection = z
  .object({
    ruling: rulingProjection,
    escalation_id: id.nullable(),
  })
  .strict();

export type RulingProjection = z.infer<typeof rulingProjection>;
export type ProposalRulingProjection = z.infer<typeof proposalRulingProjection>;

const namedActor = z.object({ id, display_name: z.string().optional() }).strict();
const targetProjection = z.object({ recipient: z.string(), resource: z.string() }).strict();

/** The current envelope without its HMAC, replay mechanics, or mutation endpoint. */
export const mandateProjection = z
  .object({
    world_id: worldId,
    mandate_id: id,
    version: integer.min(1),
    state: mandateState,
    ordering_rule: classToken,
    principal: namedActor,
    authorized_agent: namedActor,
    authority_chain: z.array(authorityHop),
    action_class: classToken,
    connected_service: id,
    target: targetProjection,
    permitted_data_fields: z.array(z.string()),
    disclosure_destinations: z.array(z.string()),
    limits: mandateLimits,
    declared_purpose: z.string().min(1),
    user_objective: z.string().min(1),
    issued_at: timestamp,
    expires_at: timestamp,
    risk_class: classToken,
    reversibility_class: classToken,
    substitution_rules: substitutionRules,
    approved_models: z.array(approvedModelEntry),
  })
  .strict();

export const mandateListProjection = z
  .object({ mandates: z.array(mandateProjection) })
  .strict();

export const approvedModelProjection = z
  .object({
    approval: approvedModelEntry,
    effective_data_classes: z.record(modelRole, restrictionTagSet),
    card_status: z.enum(['current', 'superseded', 'withdrawn']),
    signature_status: z.enum(['valid', 'invalid']),
    integrity_alarm: z.boolean(),
    current_card_digest: hexDigest.nullable(),
    verifying_key_id: id.nullable(),
    /** The signed public evidence artifact; no aggregate trust signal is added. */
    current_card: modelCard.nullable(),
  })
  .strict();

export const approvedModelsProjection = z
  .object({
    mandate_id: id,
    mandate_version: integer.min(1),
    mandate_state: mandateState,
    models: z.array(approvedModelProjection),
  })
  .strict();

/** M5.1 fixed, provider-scoped projection of authorization-owned conversation state. */
export const conversationProjection = z
  .object({
    world_id: worldId,
    case_id: id,
    provider: cardSlug,
    role: modelRole,
    items: z.array(storeItem),
    summary: z
      .object({
        included: integer.min(0),
        dropped: integer.min(0),
        dropped_item_ids: z.array(id),
        unmet_tags: restrictionTagSet,
      })
      .strict(),
  })
  .strict();

/** M5.5 durable attempt reference paired with the exact projection authorized for that call. */
export const modelCallStart = z
  .object({
    call: modelCallOpenRecord,
    projection: conversationProjection,
  })
  .strict();

export const proposalRevisionRefProjection = z
  .object({
    proposal_id: id,
    revision: integer.min(1),
    action_id: id,
  })
  .strict();

export const escalationListItemProjection = z
  .object({
    escalation_id: id,
    ruling_id: id,
    status: z.enum(['open', 'disposed', 'timed_out', 'cancelled']),
    trigger: classToken,
    eligible_role: role,
    substitute_roles: z.array(role),
    opened_at: timestamp,
    expires_at: timestamp,
    permitted_dispositions: z.array(disposition),
    terminal_disposition: disposition.nullable(),
    proposal_revision_ref: proposalRevisionRefProjection,
  })
  .strict();

export const escalationListProjection = z
  .object({ escalations: z.array(escalationListItemProjection) })
  .strict();

/** Role-routed detail for the authoritative governance origin. */
export const escalationDetailProjection = escalationListItemProjection.extend({
  question_text: z.string().min(1).nullable(),
  contract: interventionContract,
  ruling: rulingProjection,
});

/** The model-side process receives status only, never the intervention contract. */
export const escalationStatusProjection = z
  .object({
    escalation_id: id,
    status: z.enum(['open', 'disposed', 'timed_out', 'cancelled']),
    proposal_revision_ref: proposalRevisionRefProjection,
    response_bound: validityWindow,
    terminal_disposition: disposition.nullable(),
  })
  .strict();

const chainEnvelope = z
  .object({
    seq: integer.min(0),
    prev_hash: hexDigest,
    entry_hash: hexDigest,
  })
  .strict();

export const actionChainItemProjection = chainEnvelope.extend({ entry: recordEntry });
export const accessChainItemProjection = chainEnvelope.extend({ entry: accessChainEntry });

export const recordViewProjection = z
  .object({
    world_id: worldId,
    action_chain: z.object({ length: integer.min(0), entries: z.array(actionChainItemProjection) }).strict(),
    access_chain: z.object({ length: integer.min(0), entries: z.array(accessChainItemProjection) }).strict(),
  })
  .strict();

export const checkpointFactProjection = z
  .object({
    checkpoint_id: id,
    seq: integer.min(1),
    created_at: timestamp,
    composite_digest: hexDigest,
    world_streams: z.array(
      z
        .object({ stream: z.enum(['access', 'action', 'wal']), length: integer.min(0), head_hash: hexDigest })
        .strict(),
    ),
  })
  .strict();

export const recordVerificationProjection = z
  .object({
    status: z.literal('no-divergence-detected'),
    mode: z.enum(['local', 'remote']),
    checkpoint: checkpointFactProjection.nullable(),
    latest_pushed_checkpoint: z
      .object({ checkpoint: checkpointFactProjection, commit_sha: z.string().regex(/^[0-9a-f]{40,64}$/), repo_url: z.string().url() })
      .strict()
      .nullable(),
    open_window: z.object({ entries: integer.min(0), minutes: integer.min(0).nullable() }).strict(),
    warnings: z.array(z.string()),
    message: z.string().min(1),
  })
  .strict();

export const recordVerificationAlarmProjection = z
  .object({
    status: z.literal('alarm'),
    code: z.enum([
      'invalid-checkpoint',
      'checkpoint-chain',
      'pointer-rollback',
      'chain-tamper',
      'rollback',
      'missing-stream',
      'remote-mismatch',
    ]),
    message: z.literal('record verification detected a divergence'),
  })
  .strict();

export const applicantEffectProjection = z
  .object({
    entry_id: id,
    at: timestamp,
    event: z.enum(['commitment', 'effect_outcome', 'retry_served']),
    effect_id: id,
    outcome: z.enum(['success', 'failed', 'no-effect', 'unknown-reconciliation-required']).nullable(),
  })
  .strict();

export const applicantInterventionProjection = z
  .object({
    entry_id: id,
    at: timestamp,
    kind: z.enum([
      'escalation_raised',
      'disposition_recorded',
      'disposition_refused',
      'revision_continuation_refused',
      'dialogue_trigger_raised',
      'dialogue_response_recorded',
      'dialogue_response_refused',
      'dialogue_timeout',
      'escalation_timeout',
      'late_disposition_ignored',
    ]),
    disposition: disposition.nullable(),
  })
  .strict();

export const applicantActionProjection = z
  .object({
    action_id: id,
    proposal_id: id,
    revision: integer.min(1),
    declared_objective: z.string().min(1),
    proposed_action: z.string().min(1),
    target: targetProjection,
    material_consequences: z.array(z.string()),
    authority: z.object({ mandate_id: id, mandate_version: integer.min(1) }).strict(),
    ruling: rulingProjection.pick({ ruling_id: true, verdict: true, reason: true, status: true }),
    effects: z.array(applicantEffectProjection),
    interventions: z.array(applicantInterventionProjection),
    challenge_and_remedy: recordEntry.shape.challenge_and_remedy,
  })
  .strict();

export const localRecordReceiptProjection = z
  .object({
    kind: z.literal('local-record-receipt'),
    notice: z.literal('A true lodgment receipt requires independent custody, which this POC does not provide.'),
    latest_pushed_checkpoint: z
      .object({
        checkpoint_id: id,
        composite_digest: hexDigest,
        remote_commit_sha: z.string().regex(/^[0-9a-f]{40,64}$/),
        repo_url: z.string().url(),
        action_chain_length_at_anchor: integer.min(0),
      })
      .strict()
      .nullable(),
    action_entries: z.array(
      z.object({ entry_id: id, action_id: id, index: integer.min(0), inside_anchored_prefix: z.boolean() }).strict(),
    ),
    open_window: z.object({ entries: integer.min(0), minutes: integer.min(0).nullable() }).strict(),
  })
  .strict();

export const applicantExtractProjection = z
  .object({
    world_id: worldId,
    scope: z.object({ role: z.literal('applicant'), resources: z.array(z.string()) }).strict(),
    actions: z.array(applicantActionProjection),
    receipt: localRecordReceiptProjection,
  })
  .strict();

export type MandateProjection = z.infer<typeof mandateProjection>;
export type ApprovedModelsProjection = z.infer<typeof approvedModelsProjection>;
export type ConversationProjection = z.infer<typeof conversationProjection>;
export type ModelCallStart = z.infer<typeof modelCallStart>;
export type EscalationDetailProjection = z.infer<typeof escalationDetailProjection>;
export type EscalationStatusProjection = z.infer<typeof escalationStatusProjection>;
export type RecordViewProjection = z.infer<typeof recordViewProjection>;
export type RecordVerificationProjection = z.infer<typeof recordVerificationProjection>;
export type ApplicantExtractProjection = z.infer<typeof applicantExtractProjection>;
