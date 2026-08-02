// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-002 fixed allowlist projections for data crossing into the model-side process. */
import { z } from 'zod';

import { id, rulingStatus, uxClass, validityWindow, verdict } from './schemas/index.js';

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
