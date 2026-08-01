// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Commit token — ADR-001 §6.
 *
 * Single-use and short-TTL. The executing service verifies MAC and TTL locally and uses
 * it once; single use is guaranteed upstream (the nonce is consumable exactly once) and
 * again downstream (a duplicate `effect_outcome` for an `effect_id` is rejected).
 */
import { z } from 'zod';

import { classToken, hexDigest, id, jsonScalarOrList, macBlock, timestamp, worldId } from './common.js';

/**
 * The exact service request whose digest is bound into a commit token. The services host
 * recomputes the digest locally before touching its effect ledger; an orchestrator cannot
 * reuse a valid token for a different target or parameter set.
 */
export const effectIntent = z
  .object({
    world_id: worldId,
    ruling_id: id,
    frozen_proposal_hash: hexDigest,
    service: id,
    action_class: classToken,
    target: z
      .object({
        recipient: z.string().min(1),
        resource: z.string().min(1),
      })
      .strict(),
    exact_parameters: z.record(z.string(), jsonScalarOrList),
    data_to_be_disclosed: z.array(z.string()),
  })
  .strict();

export type EffectIntent = z.infer<typeof effectIntent>;

export const commitToken = z
  .object({
    world_id: worldId,
    effect_id: id,
    ruling_id: id,
    frozen_proposal_hash: hexDigest,
    /** Digest of `effectIntent` under the `effect-intent` domain. */
    effect_request_digest: hexDigest,
    /**
     * Hex SHA-256 over canonical `{world_id, ruling_id, nonce}`. Filename-safe on Windows:
     * 64 lowercase hex characters, no separators, no reserved names.
     */
    idempotency_key: hexDigest,
    service: id,
    action_class: classToken,
    expires_at: timestamp,
    /** ADR-007 MAC block under the `commit-token` domain. */
    mac: macBlock,
  })
  .strict();

export type CommitToken = z.infer<typeof commitToken>;
