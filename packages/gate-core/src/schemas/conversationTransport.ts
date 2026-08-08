// SPDX-License-Identifier: AGPL-3.0-only
/** M5.10 conversation-ingress provenance, events, and single-use output release. */
import { z } from 'zod';

import {
  cardSlug,
  hexDigest,
  id,
  integer,
  modelId,
  sortedRestrictionTags,
  timestamp,
  worldId,
} from './common.js';
import { browserOrigin } from './state.js';
import { systemUseDecisionReference } from './systemUseDecision.js';

export const CASE_OFFICER_MESSAGE_PROFILE_ID = 'case-officer-message@1' as const;
export const CASE_OFFICER_MESSAGE_TAGS = ['conf:case', 'purpose:grant-assessment'] as const;
export const CASE_OFFICER_MESSAGE_PROFILE = Object.freeze({
  schema: 'ai-charter-runtime/conversation-ingress-profile@1' as const,
  profile_id: CASE_OFFICER_MESSAGE_PROFILE_ID,
  store: 'said' as const,
  origin_actor: 'officer' as const,
  tags: CASE_OFFICER_MESSAGE_TAGS,
  provenance: Object.freeze({ derived_from: Object.freeze([]), hops: Object.freeze([]) }),
});

export const caseSessionProvenanceReceipt = z
  .object({
    world_id: worldId,
    session_id: id,
    handoff_id: id,
    role: z.literal('case_officer'),
    case_id: id,
    target_origin: browserOrigin,
    authorization_boot_id: id,
    issued_at: timestamp,
    expires_at: timestamp,
    state: z.enum(['active', 'expired']),
  })
  .strict()
  .superRefine((record, context) => {
    if (
      record.issued_at > record.expires_at ||
      Date.parse(record.expires_at) - Date.parse(record.issued_at) > 15 * 60 * 1_000
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: 'case-session provenance receipt must last no more than fifteen minutes',
      });
    }
  });
export type CaseSessionProvenanceReceipt = z.infer<typeof caseSessionProvenanceReceipt>;

export const modelCallIngressBinding = z
  .object({
    message_id: id,
    message_item_id: id,
    conversation_version: integer.min(1),
    message_digest: hexDigest,
  })
  .strict();
export type ModelCallIngressBinding = z.infer<typeof modelCallIngressBinding>;

export const conversationMessageIngressRequest = z
  .object({ message_id: id, turn_id: id, text: z.string() })
  .strict();
export type ConversationMessageIngressRequest = z.infer<typeof conversationMessageIngressRequest>;

export const conversationMessageIngressResult = z
  .object({
    kind: z.literal('conversation_message_ingress_result'),
    message_id: id,
    turn_id: id,
    message_item_id: id,
    conversation_version: integer.min(1),
    message_digest: hexDigest,
    recorded_at: timestamp,
  })
  .strict();
export type ConversationMessageIngressResult = z.infer<typeof conversationMessageIngressResult>;

const conversationEventBase = z.object({
  world_id: worldId,
  event_id: id,
  case_id: id,
  message_id: id,
  turn_id: id,
  item_id: id,
  conversation_version: integer.min(1),
  content_digest: hexDigest,
  byte_length: integer.min(1),
  recorded_at: timestamp,
});

export const conversationMessageIngressEvent = conversationEventBase
  .extend({
    kind: z.literal('message_ingress'),
    session_id: id,
    ingress_profile_id: z.literal(CASE_OFFICER_MESSAGE_PROFILE_ID),
    ingress_profile_digest: hexDigest,
  })
  .strict();

export const conversationModelOutputIngressEvent = conversationEventBase
  .extend({
    kind: z.literal('model_output_ingress'),
    release_id: id,
    requested_id: modelId,
    served_id: modelId,
  })
  .strict();

export const conversationIngressEvent = z.discriminatedUnion('kind', [
  conversationMessageIngressEvent,
  conversationModelOutputIngressEvent,
]);
export type ConversationIngressEvent = z.infer<typeof conversationIngressEvent>;

export const outputReleaseState = z.enum(['issued', 'consumed', 'invalidated', 'expired']);
export const outputReleaseConsumptionResult = z
  .object({
    event_id: id,
    item_id: id,
    conversation_version: integer.min(1),
    recorded_at: timestamp,
  })
  .strict();
export type OutputReleaseConsumptionResult = z.infer<typeof outputReleaseConsumptionResult>;

export const outputReleaseRecord = z
  .object({
    world_id: worldId,
    release_id: id,
    authorization_boot_id: id,
    call_id: id,
    case_id: id,
    turn_id: id,
    session_id: id,
    message_id: id,
    message_item_id: id,
    conversation_version: integer.min(1),
    selection_id: id,
    mandate_id: id,
    mandate_version: integer.min(1),
    card_id: cardSlug,
    card_version: integer.min(1),
    card_digest: hexDigest,
    verifying_key_id: id,
    requested_id: modelId,
    served_id: modelId,
    system_use_decision: systemUseDecisionReference,
    policy_version: z.string().min(1),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    projection_item_ids: z.array(id),
    projection_digest: hexDigest,
    output_digest: hexDigest,
    derived_tags: sortedRestrictionTags,
    issued_at: timestamp,
    expires_at: timestamp,
    state: outputReleaseState,
    state_changed_at: timestamp,
    invalidation_reason: z.string().min(1).nullable(),
    consumption_result: outputReleaseConsumptionResult.nullable(),
  })
  .strict()
  .superRefine((record, context) => {
    if (
      record.issued_at > record.expires_at ||
      Date.parse(record.expires_at) - Date.parse(record.issued_at) > 2 * 60 * 1_000
    ) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: 'output release must last no more than two minutes',
      });
    }
    if (record.state_changed_at < record.issued_at) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['state_changed_at'],
        message: 'output release state cannot change before issue',
      });
    }
    if ((record.state === 'consumed') !== (record.consumption_result !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['consumption_result'],
        message: 'only a consumed release carries a consumption result',
      });
    }
    if ((record.state === 'invalidated') !== (record.invalidation_reason !== null)) {
      context.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['invalidation_reason'],
        message: 'only an invalidated release carries an invalidation reason',
      });
    }
  });
export type OutputReleaseRecord = z.infer<typeof outputReleaseRecord>;

export const outputReleaseReference = z
  .object({ release_id: id, call_id: id, expires_at: timestamp })
  .strict();
export type OutputReleaseReference = z.infer<typeof outputReleaseReference>;

export const outputReleaseConsumeRequest = z.object({ content: z.string() }).strict();
export type OutputReleaseConsumeRequest = z.infer<typeof outputReleaseConsumeRequest>;

export const outputReleaseConsumeResult = z
  .object({
    kind: z.literal('output_release_consumption_result'),
    release_id: id,
    state: z.literal('consumed'),
    event_id: id,
    item_id: id,
    conversation_version: integer.min(1),
    recorded_at: timestamp,
  })
  .strict();
export type OutputReleaseConsumeResult = z.infer<typeof outputReleaseConsumeResult>;

export const outputReleaseStatusProjection = z
  .object({
    kind: z.literal('output_release_status'),
    release_id: id,
    call_id: id,
    state: outputReleaseState,
    issued_at: timestamp,
    expires_at: timestamp,
    state_changed_at: timestamp,
    consumption_result: outputReleaseConsumptionResult.nullable(),
  })
  .strict();
export type OutputReleaseStatusProjection = z.infer<typeof outputReleaseStatusProjection>;

const conversationProcessEventBase = z.object({
  message_id: id,
  turn_id: id,
  text: z.string(),
  recorded_at: timestamp,
});

export const conversationProcessEvent = z.discriminatedUnion('speaker', [
  conversationProcessEventBase.extend({ speaker: z.literal('case_officer') }).strict(),
  conversationProcessEventBase
    .extend({
      speaker: z.literal('model'),
      requested_id: modelId,
      served_id: modelId,
      classification: z.literal('inferred-unconfirmed'),
    })
    .strict(),
]);
export type ConversationProcessEvent = z.infer<typeof conversationProcessEvent>;

export const conversationProcessProjection = z
  .object({
    case_id: id,
    conversation_version: integer.min(0),
    events: z.array(conversationProcessEvent).max(128),
  })
  .strict();
export type ConversationProcessProjection = z.infer<typeof conversationProcessProjection>;

/** Content-free evidence permitted in the access chain for the four M5.10 process routes. */
export const conversationTransportAccessEvidence = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('conversation_message_ingress'),
      case_id: id,
      message_id: id,
      turn_id: id,
      item_id: id,
      conversation_version: integer.min(1),
      content_digest: hexDigest,
      byte_length: integer.min(1),
      ingress_profile_id: z.literal(CASE_OFFICER_MESSAGE_PROFILE_ID),
      ingress_profile_digest: hexDigest,
      recorded_at: timestamp,
    })
    .strict(),
  z
    .object({
      kind: z.literal('output_release_consumed'),
      release_id: id,
      call_id: id,
      case_id: id,
      turn_id: id,
      event_id: id,
      item_id: id,
      conversation_version: integer.min(1),
      state: z.literal('consumed'),
      recorded_at: timestamp,
    })
    .strict(),
  outputReleaseStatusProjection,
  z
    .object({
      kind: z.literal('conversation_read'),
      case_id: id,
      conversation_version: integer.min(0),
      event_count: integer.min(0).max(128),
      utf8_bytes: integer.min(0).max(256 * 1_024),
    })
    .strict(),
]);
export type ConversationTransportAccessEvidence = z.infer<typeof conversationTransportAccessEvidence>;
