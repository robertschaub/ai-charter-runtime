// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Action mandate — spec §4 (the §7.1 field list plus the approved acting-model set),
 * ADR-006 §4 (how mandates reference cards), ADR-007 (HMAC binding).
 */
import { z } from 'zod';

import {
  cardSlug,
  classToken,
  hexDigest,
  id,
  integer,
  macBlock,
  modelId,
  modelRole,
  nonNegativeMinorUnits,
  restrictionTagSet,
  timestamp,
  validityWindow,
  worldId,
} from './common.js';

/**
 * ADR-006 §4: each approved-model entry is role-scoped and pins `card_version` **and**
 * `card_digest`. The digest is taken over exactly the signed bytes — the canonical card
 * minus its `signature` block — so digest equality means signed-content equality and
 * re-signing under a rotated key leaves the digest untouched.
 */
export const approvedModelEntry = z
  .object({
    card_id: cardSlug,
    card_version: integer.min(1),
    card_digest: hexDigest,
    requested_id: modelId,
    roles: z
      .array(modelRole)
      .min(1)
      .refine((roles) => new Set(roles).size === roles.length, 'roles must be unique'),
    data_classes: z.record(modelRole, restrictionTagSet),
    /**
     * ADR-006 §5: set by the service when the pinned digest no longer matches the current
     * card file. The model keeps acting, but the next Authorize-class transaction on this
     * mandate cannot complete until the principal re-confirms or drops the entry.
     */
    re_confirmation_required: z.boolean().optional(),
  })
  .strict()
  .superRefine((entry, ctx) => {
    for (const role of entry.roles) {
      if (entry.data_classes[role] === undefined) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['data_classes', role],
          message: `role ${role} is approved but has no data_classes (ADR-006 §4)`,
        });
      }
    }
    for (const role of Object.keys(entry.data_classes)) {
      if (!(entry.roles as readonly string[]).includes(role)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['data_classes', role],
          message: `data_classes names ${role}, which is not an approved role`,
        });
      }
    }
  });

export type ApprovedModelEntry = z.infer<typeof approvedModelEntry>;

export const defaultActingModel = z
  .object({ card_id: cardSlug, card_version: integer.min(1), requested_id: modelId })
  .strict();
export type DefaultActingModel = z.infer<typeof defaultActingModel>;

/** One hop of the authority chain, carrying its own subdelegation scope (spec §7.1). */
export const authorityHop = z.object({
  hop: integer.min(0),
  delegator: id,
  delegate: id,
  subdelegation_scope: z.array(z.string()),
}).strict();

export const MANDATE_STATES = ['active', 'suspended', 'expired', 'revoked'] as const;
export const mandateState = z.enum(MANDATE_STATES);

/** Amount, frequency, volume, geographic and time limits — integers in minor units. */
export const mandateLimits = z.object({
  amount_minor_units: nonNegativeMinorUnits.optional(),
  frequency_per_day: integer.min(0).optional(),
  notification_volume: integer.min(0).optional(),
  geographic: z.array(z.string()).optional(),
  time_window: validityWindow,
}).strict();

/** Spec §5: a substitution that widens the envelope is defective authority, not a hop. */
export const substitutionRules = z.object({
  model_substitution: z.enum(['not-permitted', 'approved-set-only']),
  service_substitution: z.enum(['not-permitted', 'named-services-only']),
}).strict();

export const mandate = z
  .object({
  /** ADR-002 §6: every stored object carries `world_id` as its first field. */
  world_id: worldId,
  mandate_id: id,
  /** Monotonic; every amendment is a new version and is re-bound (ADR-007). */
  version: integer.min(1),
  state: mandateState,
  /**
   * Criterion 3's ordering rule for overlapping or changed mandates. The sources name the
   * field but do not enumerate its values, so this stays a token rather than an invented enum.
   */
  ordering_rule: classToken,

  principal: z.object({ id, display_name: z.string().optional() }).strict(),
  authorized_agent: z.object({ id, display_name: z.string().optional() }).strict(),
  authority_chain: z.array(authorityHop),

  action_class: classToken,
  connected_service: id,
  target: z.object({
    recipient: z.string().min(1),
    resource: z.string().min(1),
  }).strict(),

  permitted_data_fields: z.array(z.string()),
  disclosure_destinations: z.array(z.string()),
  limits: mandateLimits,

  declared_purpose: z.string().min(1),
  user_objective: z.string().min(1),

  issued_at: timestamp,
  expires_at: timestamp,
  revocation_endpoint: z.string().min(1),
  replay_protection: z.object({ scheme: z.literal('per-ruling-nonce') }).strict(),

  substitution_rules: substitutionRules,
  risk_class: classToken,
  reversibility_class: classToken,

  /** Spec §4: the operating envelope names the system allowed to act. */
  approved_models: z.array(approvedModelEntry).min(1),
  /** ADR-009: an exact HMAC-bound default, never array order or software configuration. */
  default_acting_model: defaultActingModel,

  /**
   * ADR-007: HMAC-SHA256 over the canonical mandate minus this field, domain
   * `mandate-binding`, so every amendment is re-bound. An `invalid` **or**
   * `unverifiable` binding is defective authority — deny.
   */
    binding: macBlock,
  })
  .strict()
  .superRefine((value, ctx) => {
    const modelKeys = value.approved_models.map((entry) => `${entry.card_id}\u0000${entry.requested_id}`);
    if (new Set(modelKeys).size !== modelKeys.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['approved_models'],
        message: 'approved model entries must be unique by card and requested id',
      });
    }
    if (!value.approved_models.some((entry) => entry.roles.includes('acting'))) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['approved_models'],
        message: 'a mandate must approve at least one acting model',
      });
    }
    if (
      !value.approved_models.some(
        (entry) =>
          entry.card_id === value.default_acting_model.card_id &&
          entry.card_version === value.default_acting_model.card_version &&
          entry.requested_id === value.default_acting_model.requested_id &&
          entry.roles.includes('acting'),
      )
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['default_acting_model'],
        message: 'default acting model must exactly match an approved acting entry',
      });
    }
    if (value.issued_at > value.expires_at) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['expires_at'],
        message: 'mandate expiry must not precede issuance',
      });
    }
    const hops = [...value.authority_chain].sort((left, right) => left.hop - right.hop);
    for (let index = 0; index < hops.length; index += 1) {
      const hop = hops[index];
      if (hop?.hop !== index) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['authority_chain'],
          message: 'authority-chain hop numbers must be contiguous from zero',
        });
        break;
      }
      const previous = hops[index - 1];
      if (previous !== undefined && previous.delegate !== hop.delegator) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['authority_chain', index, 'delegator'],
          message: 'each authority hop must continue from the previous delegate',
        });
      }
    }
  });

export type Mandate = z.infer<typeof mandate>;
