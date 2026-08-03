// SPDX-License-Identifier: AGPL-3.0-only
/** M5.2 exact synthetic screening fixtures for deterministic offline signal plumbing. */
import { z } from 'zod';

import { cardSlug, hexDigest, id, screeningSignal } from './schemas/index.js';

export const screeningFixture = z
  .object({
    proposal_hash: hexDigest,
    gate: z.enum(['submit', 'verify']),
    provider: cardSlug,
    suspect_item_ids: z
      .array(id)
      .min(1)
      .refine((values) => new Set(values).size === values.length, 'suspect item ids must be unique')
      .refine(
        (values) => values.every((value, index) => index === 0 || (values[index - 1] as string) < value),
        'suspect item ids must use deterministic sort order',
      ),
    signals: z.array(screeningSignal),
  })
  .strict();

export const screeningFixtureSet = z
  .array(screeningFixture)
  .refine(
    (fixtures) =>
      new Set(fixtures.map((fixture) => `${fixture.proposal_hash}\u0000${fixture.gate}`)).size === fixtures.length,
    'screening fixtures must be unique per proposal hash and gate',
  );

export type ScreeningFixture = z.infer<typeof screeningFixture>;
