// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-006 §3 — alias vs snapshot pinning; the beat-21 served-id comparison.
 *
 * A pure function of `(requested_id, resolution.policy, served_id)`:
 *
 * | Lane       | Policy                    | Accepted served ids                                     |
 * |------------|---------------------------|---------------------------------------------------------|
 * | `publicai` | `exact-match-required`    | `served == requested` only                                |
 * | `openai`   | `alias-to-dated-snapshot` | `served == requested`, or `^<escaped requested>-\d{4}-\d{2}-\d{2}$` |
 *
 * Anything else — **including a missing or malformed served id** — is a mismatch, which
 * quarantines the response and halts the lane. The served id is provider-supplied
 * evidence, so every argument is treated as untrusted and the function fails closed.
 */

export const RESOLUTION_POLICIES = ['exact-match-required', 'alias-to-dated-snapshot'] as const;
export type ResolutionPolicy = (typeof RESOLUTION_POLICIES)[number];

export type ServedIdComparison = 'exact' | 'benign-resolution' | 'mismatch';

/** Printable ASCII, no spaces — covers `gpt-5.5` and `swiss-ai/apertus-v1.5-70b`. */
const MODEL_ID = /^[\x21-\x7e]+$/;

export function isResolutionPolicy(value: unknown): value is ResolutionPolicy {
  return typeof value === 'string' && (RESOLUTION_POLICIES as readonly string[]).includes(value);
}

/** A usable model id: a string of printable, space-free ASCII with no stray whitespace. */
export function isWellFormedModelId(value: unknown): value is string {
  return typeof value === 'string' && MODEL_ID.test(value);
}

function escapeForRegExp(literal: string): string {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** `^<escaped requested>-\d{4}-\d{2}-\d{2}$` — the dated-snapshot form of an alias. */
export function datedSnapshotPattern(requestedId: string): RegExp {
  return new RegExp(`^${escapeForRegExp(requestedId)}-\\d{4}-\\d{2}-\\d{2}$`);
}

export function compareServedId(
  requestedId: unknown,
  policy: unknown,
  servedId: unknown,
): ServedIdComparison {
  if (!isWellFormedModelId(requestedId)) return 'mismatch';
  if (!isResolutionPolicy(policy)) return 'mismatch';
  if (!isWellFormedModelId(servedId)) return 'mismatch';

  if (servedId === requestedId) return 'exact';
  if (policy === 'exact-match-required') return 'mismatch';
  return datedSnapshotPattern(requestedId).test(servedId) ? 'benign-resolution' : 'mismatch';
}
