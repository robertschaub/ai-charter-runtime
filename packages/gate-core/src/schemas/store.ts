// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-005 §3 — serialization on the four stores.
 *
 * Every item carries a de-duplicated, sorted `tags` array. Items in `said`, `confirmed`
 * and `permitted` additionally carry `origin_actor` — whose testimony, confirmation, or
 * grant the item is, set at the entry boundary exactly like tags, never from model
 * output. `inferred` items carry none; their standing follows `provenance.derived_from`,
 * and ADR-004's `standing_class` derivation reads this field.
 */
import { z } from 'zod';

import { id, modelId, sortedRestrictionTags } from './common.js';

export const STORES = ['said', 'inferred', 'confirmed', 'permitted'] as const;
export const store = z.enum(STORES);
export type Store = (typeof STORES)[number];

/** One model call (request -> response) or one tool-output ingestion (ADR-005 §4). */
export const provenanceHop = z.object({
  requested: modelId,
  served: modelId,
}).strict();

export const provenance = z.object({
  derived_from: z.array(id),
  hops: z.array(provenanceHop),
}).strict();

/** `officer`, `applicant`, or `document:<doc-id>` (ADR-005 §3). */
export const originActor = z.union([
  z.enum(['officer', 'applicant']),
  z.string().regex(/^document:[a-z0-9][a-z0-9_.-]*$/, 'expected document:<doc-id>'),
]);

const ORIGIN_ACTOR_STORES = new Set(['said', 'confirmed', 'permitted']);

export const storeItem = z
  .object({
    id,
    store,
    /** The turn the item was created in — one model call or one tool ingestion. */
    turn: id.optional(),
    text: z.string(),
    provenance,
    tags: sortedRestrictionTags,
    origin_actor: originActor.optional(),
  })
  .strict()
  .superRefine((item, ctx) => {
    const required = ORIGIN_ACTOR_STORES.has(item.store);
    if (required && item.origin_actor === undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['origin_actor'],
        message: `origin_actor is required on ${item.store} items (ADR-005 §3)`,
      });
    }
    if (!required && item.origin_actor !== undefined) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['origin_actor'],
        message: 'inferred items carry no origin_actor; standing follows provenance.derived_from',
      });
    }
  });

export type StoreItem = z.infer<typeof storeItem>;
