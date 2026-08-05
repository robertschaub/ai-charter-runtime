// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Structured proposal — spec §4 (baseline point 2 of the Charter Commitments).
 *
 * Proposals are frozen (hashed) before ruling; a changed proposal is a new proposal, so
 * `revision` and `proposal_hash` are part of the artifact rather than metadata about it.
 * Material inputs and derived claims are store items, because ADR-005 requires `tags` on
 * every one of them.
 */
import { z } from 'zod';

import {
  cardSlug,
  classToken,
  hexDigest,
  id,
  integer,
  jsonScalarOrList,
  modelId,
  nonNegativeMinorUnits,
  timestamp,
  worldId,
} from './common.js';
import { storeItem } from './store.js';

export const frozenProposal = z.object({
  world_id: worldId,
  proposal_id: id,
  /** A changed proposal is a new proposal; revisions are monotonic within an action. */
  revision: integer.min(1),
  action_id: id,
  /** ADR-009: current case selection; prevents A -> B -> A authority revival. */
  selection_id: id,
  created_at: timestamp,

  declared_objective: z.string().min(1),
  proposed_action: z.string().min(1),
  target: z.object({
    recipient: z.string(),
    resource: z.string(),
  }).strict(),
  /** Integer-only regime: no float can reach the frozen hash. */
  exact_parameters: z.record(z.string(), jsonScalarOrList),

  material_inputs: z.array(storeItem),
  derived_claims: z.array(storeItem),

  data_to_be_disclosed: z.array(z.string()),
  cost_obligation: z.object({
    amount_minor_units: nonNegativeMinorUnits,
    description: z.string(),
  }).strict(),
  material_consequences: z.array(z.string()),
  reversibility_class: classToken,
  /** Kept even where it does not apply, per spec §4 ("n/a in this scenario, field kept"). */
  commercial_influence: z.object({
    applicable: z.boolean(),
    note: z.string(),
  }).strict(),

  /** The acting model is part of the ruling's binding tuple (spec §4, ADR-001 §4). */
  acting_model: z.object({
    requested_id: modelId,
    served_id: modelId,
    card_id: cardSlug,
    card_version: integer.min(1),
  }).strict(),
  mandate_ref: z.object({
    mandate_id: id,
    version: integer.min(1),
  }).strict(),

  /** ADR-007 digest, domain `proposal`, over the proposal minus this field. */
  proposal_hash: hexDigest,
}).strict();

export type FrozenProposal = z.infer<typeof frozenProposal>;
