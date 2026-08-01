// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Model card and card revocation — ADR-006 §2 and §5.
 *
 * Cards are the v0 evidence registry: signed JSON in git, bound to the pinned deployed
 * version, every substantive field a `{value, provenance, date}` triple with
 * `provenance ∈ {self-declared, probe-tested}` — there is deliberately no third value,
 * because nothing here is independently attested.
 *
 * The signature is embedded and covers the canonical card *minus that block*, domain
 * `model-card`; the revocation uses the same convention under `card-revocation`, so a
 * revocation digest can never be replayed as a card digest.
 */
import { z } from 'zod';

import { RESOLUTION_POLICIES } from '../servedModel.js';
import {
  cardSlug,
  id,
  integer,
  isoDate,
  modelId,
  modelRole,
  restrictionTagSet,
  signatureBlock,
  timestamp,
} from './common.js';

export const PROVENANCE_VALUES = ['self-declared', 'probe-tested'] as const;
export const provenanceValue = z.enum(PROVENANCE_VALUES);

/** `{ value, provenance, date }` — the shape every substantive card field takes. */
export function provenanceTriple<T extends z.ZodTypeAny>(value: T) {
  return z.object({
    value,
    provenance: provenanceValue,
    date: isoDate,
  });
}

export const PINNING_MODES = ['alias', 'exact'] as const;
export const pinningMode = z.enum(PINNING_MODES);

/** ADR-006 §3 — the lane's declared resolution behaviour, shared with `servedModel.ts`. */
export const resolutionPolicy = z.enum(RESOLUTION_POLICIES);

export const LANES = ['openai', 'publicai'] as const;
export const lane = z.enum(LANES);

export const cardResolution = z.object({
  lane,
  policy: resolutionPolicy,
  snapshot_pattern: z.string().min(1),
  observed_snapshots: z.array(
    z.object({
      id: modelId,
      first_seen: isoDate,
    }),
  ),
});

export const modelCard = z
  .object({
    schema: z.literal('ai-charter-runtime/model-card@1'),
    card_id: cardSlug,
    /** Monotonic integer: an evidence artifact has no meaningful major/minor distinction. */
    card_version: integer.min(1),
    valid_from: isoDate,
    attestation: z.literal('self-declared or probe-tested — never independently attested'),

    model: z.object({
      requested_id: modelId,
      pinning_mode: pinningMode,
      resolution: cardResolution,
    }),

    operator: provenanceTriple(z.string().min(1)),
    endpoint: provenanceTriple(z.string().min(1)),
    jurisdiction: provenanceTriple(z.string().min(1)),
    openness_class: provenanceTriple(z.string().min(1)),

    capabilities: z.object({
      tools: provenanceTriple(z.boolean()),
      response_format: provenanceTriple(z.array(z.string())),
      token_parameter: provenanceTriple(z.string().min(1)),
    }),

    evidence_status: z.object({
      as_of: isoDate,
      source: z.string().min(1),
      /** What was *not* checked, and why — the check-surface guard. */
      not_checked: z.array(z.object({ item: z.string().min(1), why: z.string().min(1) })),
    }),

    known_limits: z.array(provenanceTriple(z.string().min(1))),

    /** ADR-005 vocabulary; the mandate governs, the card can narrow but never widen. */
    declared_data_classes: z.record(modelRole, restrictionTagSet),

    signature: signatureBlock,
  })
  .superRefine((card, ctx) => {
    const expectedExact = card.model.resolution.policy === 'exact-match-required';
    if (expectedExact !== (card.model.pinning_mode === 'exact')) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['model', 'pinning_mode'],
        message: 'pinning_mode and resolution.policy must agree (ADR-006 §3)',
      });
    }
  });

export type ModelCard = z.infer<typeof modelCard>;

/**
 * ADR-006 §5 — a signed security withdrawal. An unverifiable revocation still suspends and
 * raises an integrity alarm: an unverifiable withhold-signal can only withhold, never
 * grant, so honouring it is the fail-closed reading.
 */
export const cardRevocation = z.object({
  card_id: cardSlug,
  revokes_versions: z.union([z.literal('all'), z.array(integer.min(1)).min(1)]),
  reason_class: z.enum(['security', 'evidence-withdrawn', 'operator-request']),
  effective_at: timestamp,
  issued_by: z.string().min(1),
  signature: signatureBlock,
});

export type CardRevocation = z.infer<typeof cardRevocation>;

/** ADR-007: the committed trust root — public verification keys only, never a `.pem`. */
export const signingKeyEntry = z.object({
  key_id: id,
  alg: z.literal('ed25519'),
  /** SPKI DER, base64. */
  public_key_b64: z.string().min(1),
  created: isoDate,
  retired_at: isoDate.optional(),
  /** A revoked key stops every card it signed from verifying (ADR-006 §5). */
  revoked_at: isoDate.optional(),
});

export const signingKeys = z.array(signingKeyEntry);

export type SigningKeyEntry = z.infer<typeof signingKeyEntry>;
