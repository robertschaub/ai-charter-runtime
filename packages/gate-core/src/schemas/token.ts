// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Commit token — ADR-001 §6.
 *
 * Single-use and short-TTL. The executing service verifies MAC and TTL locally and uses
 * it once; single use is guaranteed upstream (the nonce is consumable exactly once) and
 * again downstream (a duplicate `effect_outcome` for an `effect_id` is rejected).
 */
import { z } from 'zod';

import { classToken, hexDigest, id, macBlock, timestamp, worldId } from './common.js';

export const commitToken = z.object({
  world_id: worldId,
  effect_id: id,
  ruling_id: id,
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
});

export type CommitToken = z.infer<typeof commitToken>;
